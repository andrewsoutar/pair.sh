#define _GNU_SOURCE

#include <stdlib.h>
#include <stdatomic.h>
#include <stdbool.h>

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>

#include <sys/types.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include "log.h"

#include "include-config.h"

struct io_callback {
  enum {
    IO_SIGHAND_SIGNALED,
    IO_NET_CONN_TIMEOUT,
    IO_HAPPY_EYEBALLS_CONNECT
  } tag;
};

typedef struct io_fd {
  size_t index;
  struct io_callback *pollin_cb, *pollout_cb;
} *io_fd_t;

struct event_loop {
  void **fds, **close_fd;
  struct pollfd *pollfds;
  struct io_timer *timer;
  size_t n_fds, alloc_size;
  bool terminated;
};

static void io_dispatch(struct event_loop *ev, struct io_callback *cb,
                        void *extra);

static int event_loop_init(struct event_loop *ev) {
  ev->alloc_size = 16;

  ev->fds = malloc(sizeof *ev->fds * ev->alloc_size);
  if (ev->fds == NULL)
    return -ENOMEM;

  ev->pollfds = malloc(sizeof *ev->pollfds * ev->alloc_size);
  if (ev->pollfds == NULL) {
    free(ev->fds);
    return -ENOMEM;
  }

  ev->close_fd = NULL;
  ev->timer = NULL;
  ev->n_fds = 0;
  ev->terminated = false;

  return 0;
}

static void event_loop_cleanup(struct event_loop *ev) {
  assert(ev->n_fds == 0);
  assert(ev->timer == NULL);
  free(ev->fds);
  free(ev->pollfds);
}


static int io_raw_fd(struct event_loop *ev, io_fd_t fd) {
  int raw_fd = ev->pollfds[fd->index].fd;
  if (raw_fd < 0)
    raw_fd = -(raw_fd + 1);
  return raw_fd;
}

static int io_make_fd(struct event_loop *ev, io_fd_t *io_fd, int raw_fd) {
  int ret;

  if (raw_fd < 0)
    return -EBADF;

  ret = -EMFILE;
  if (-raw_fd < INT_MIN + 1)
    goto out;

  ret = -ENOMEM;
  if (ev->n_fds == ev->alloc_size) {
    void *new_mem;
    size_t new_alloc_size = 2 * ev->alloc_size;

    new_mem = realloc(ev->fds, new_alloc_size * sizeof *ev->fds);
    if (new_mem == NULL)
      goto out;
    ev->fds = new_mem;

    new_mem = realloc(ev->fds, new_alloc_size * sizeof *ev->pollfds);
    if (new_mem == NULL)
      goto out;
    ev->pollfds = new_mem;

    ev->alloc_size = new_alloc_size;
  }

  *io_fd = malloc(sizeof **io_fd);
  if (*io_fd == NULL)
    goto out;

  ret = fcntl(raw_fd, F_GETFD);
  if (ret < 0) {
    ret = -errno;
    goto out;
  }
  ret = fcntl(raw_fd, F_SETFD, ret | FD_CLOEXEC);
  if (ret) {
    ret = -errno;
    goto out;
  }

  ret = fcntl(raw_fd, F_GETFL);
  if (ret < 0) {
    ret = -errno;
    goto out;
  }
  ret = fcntl(raw_fd, F_SETFL, ret | O_NONBLOCK);
  if (ret) {
    ret = -errno;
    goto out;
  }

  **io_fd = (struct io_fd) { .index = ev->n_fds++ };
  ev->fds[(*io_fd)->index] = *io_fd;
  ev->pollfds[(*io_fd)->index] = (struct pollfd) { .fd = -raw_fd - 1 };
  return 0;

out:
  close(raw_fd);
  return ret;
}

static void io_close(struct event_loop *ev, io_fd_t fd) {
  if (ev->pollfds[fd->index].events & POLLNVAL)
    return;

  /* Don't worry about errors on close */
  close(io_raw_fd(ev, fd));

  ev->pollfds[fd->index].fd = -1;
  ev->pollfds[fd->index].events = POLLNVAL;
  ev->fds[fd->index] = ev->close_fd;
  ev->close_fd = &ev->fds[fd->index];
  free(fd);
}

static void io_dispatch_callback_by_index(struct event_loop *ev, short event,
                                          size_t i, void *extra) {
  struct io_fd *fd;
  struct io_callback *cb, **cb_p;
  if (!(ev->pollfds[i].events & POLLNVAL)) {
    fd = ev->fds[i];
    if (event == POLLIN)
      cb_p = &fd->pollin_cb;
    else
      cb_p = &fd->pollout_cb;
    cb = *cb_p;

    ev->pollfds[i].events &= (short) ~event;
    *cb_p = NULL;

    io_dispatch(ev, cb, extra);
  }
}

static void io_register_read_callback(struct event_loop *ev, io_fd_t fd,
                                       struct io_callback *cb) {
  ev->pollfds[fd->index].fd = io_raw_fd(ev, fd);
  ev->pollfds[fd->index].events |= POLLIN;
  fd->pollin_cb = cb;
}

static void io_register_write_callback(struct event_loop *ev, io_fd_t fd,
                                       struct io_callback *cb) {
  ev->pollfds[fd->index].fd = io_raw_fd(ev, fd);
  ev->pollfds[fd->index].events |= POLLOUT;
  fd->pollout_cb = cb;
}


struct io_timer {
  struct io_callback *cb;
  /*
   * FIXME these pointers implement a min-heap with a fairly complex
   * structure, documentation needed
   */
  /*
   * These pointers implement a threaded min-heap, with the key being
   * the expiration of the timer. The heap has a fairly complex
   * structure so that it can be implemented using only three pointers
   * (a naive implementation requires five - left child, right child,
   * parent, next node, prev node).
   *
   * next - always points to the "next" node in a wraparound traversal
   * of the tree. This is a traversal which starts at the root and
   * traverses each level left-to-right, wrapping around to the next
   * level when it reaches the end of the one it's on. If the last
   * node in this traversal is a left child, its next pointer points
   * to its parent (because its prev node does not - see below),
   * otherwise its next node is null.
   *
   * child - always points to a node's left child. Since the heap is
   * always a left-filled binary tree, any node which has a child has
   * a left child. The right child, if any, is accessed using the left
   * child's next pointer.
   *
   * prev - on a left child, points to the previous node in the
   * wraparound traversal. On a right child, points to the parent (a
   * left child can access its parent using next->prev). On the root,
   * points to the last node in a wraparound traversal of the tree. (A
   * new node added to the heap will be added at a point in the
   * wraparound traversal directly after this node, to maintain the
   * left-filled-tree property.)
   *
   * Beyond that mess of a tree structure, this is just a plain old
   * min-heap.
   */
  struct io_timer *child, *prev, *next;
  struct timespec time;
  unsigned long duration_ns;
};

static void io_timer_init(struct io_timer *timer) {
  timer->prev = NULL;
}

static const unsigned long sec = 1000000000ul;

_Pragma("GCC diagnostic push")
_Pragma("GCC diagnostic ignored \"-Wsign-compare\"")
_Pragma("GCC diagnostic ignored \"-Wsign-conversion\"")
static unsigned long
do_checked_time_subtract(const struct timespec *restrict t1,
                         const struct timespec *restrict t2)
{
  const unsigned long bound = ULONG_MAX / sec + 1;
  long delta_ns;
  unsigned long ret;

  assert(t1->tv_sec > t2->tv_sec);

  /*
   * This basically returns t1 - t2, clamped to [0, ULONG_MAX]. It's
   * complicated because it needs to account for various overflows
   * along the way.
   */

  if (t1->tv_sec <= 0 || t2->tv_sec >= 0) {
    /*
     * They both have the same sign (see assertion) and the result
     * will be positive, so subtraction will never overflow time_t
     * here, and will also never overflow the common real type of
     * time_t and unsigned long
     */
    if (t1->tv_sec - t2->tv_sec > bound)
      return 0;
    ret = (unsigned long) (t1->tv_sec - t2->tv_sec);
  } else if (-(t2->tv_sec + 1) > bound - 1 || t1->tv_sec > bound + t2->tv_sec)
    return 0;
  else
    ret = (unsigned long) t1->tv_sec - (unsigned long) t2->tv_sec;
  assert(ret != 0);

  delta_ns = t1->tv_nsec - t2->tv_nsec;

  /*
   * ret <= bound, so ret * sec <= ULONG_MAX + 1*sec, therefore it can
   * only overflow for a single wraparound. We let the multiplication
   * overflow, because it might be underflowed back down again by
   * delta_ns, and we can check both later.
   */
  ret = ret * sec + delta_ns;
  /*
   * ret >= 1, so without overflow, we should have increased by >=
   * 1*sec. If there was an overflow, in the worst case ret == bound,
   * and so we've overflowed by at most 2*sec (one for the +1 in
   * bound, one for delta_ns). Since 2*sec < ULONG_MAX, we've
   * overflowed by at most 1 wraparound. We know by definition that
   * bound * sec <= ULONG_MAX + 1*sec, so the difference when we
   * overflow is, at most, ULONG_MAX + 1*sec - (ULONG_MAX + 1), and
   * therefore < 1*sec. Therefore, we can use this condition to check
   * if the eventual result from the computation has overflowed.
   */
  if (ret < 1 * sec + delta_ns)
    return 0;

  return ret;
}
_Pragma("GCC diagnostic pop")

static unsigned long io_timer_remaining(struct io_timer *restrict timer,
                                        struct timespec *restrict time) {
  unsigned long ret;

  assert(timer->time.tv_nsec >= 0 && timer->time.tv_nsec < 1000000000);
  assert(time->tv_nsec >= 0 && time->tv_nsec < 1000000000);

  /* do_checked_time_subtract only works when the seconds field is non-equal */
  if (time->tv_sec == timer->time.tv_sec) {
    long delta_ns = timer->time.tv_nsec - time->tv_nsec;
    if (delta_ns >= 0) {
      if (timer->duration_ns > ULONG_MAX - (unsigned long) delta_ns)
        return ULONG_MAX;
    } else {
      if (timer->duration_ns < (unsigned long) -delta_ns)
        return 0;
    }
    return timer->duration_ns + (unsigned long) delta_ns;
  }

  if (time->tv_sec > timer->time.tv_sec) {
    /* We're definitely in the future, calculate elapsed time */
    ret = do_checked_time_subtract(time, &timer->time);
    if (!ret || ret > timer->duration_ns)
      return 0;
    return timer->duration_ns - ret;
  } else {
    /* Timer hasn't started yet somehow, calculate time until timer starts */
    ret = do_checked_time_subtract(&timer->time, time);
    if (!ret || ret > ULONG_MAX - timer->duration_ns)
      return ULONG_MAX;
    return timer->duration_ns + ret;
  }
}

static bool io_timer_swap_parent_child(struct io_timer **root_p,
                                       struct io_timer *parent,
                                       struct io_timer *child) {
  unsigned long remaining;
  struct io_timer *tmp;

  remaining = io_timer_remaining(parent, &child->time);
  if (remaining != UINT_MAX && remaining <= child->duration_ns)
    return false;

  /* Swap outgoing pointers */
  tmp = parent->child;
  parent->child = child->child;
  child->child = tmp;

  tmp = parent->prev;
  parent->prev = child->prev;
  child->prev = tmp;

  tmp = parent->next;
  parent->next = child->next;
  child->next = tmp;

  /* Swap parent and child pointers to make fixups more clear */
  tmp = parent;
  parent = child;
  child = tmp;

  if (*root_p == child) {
    *root_p = parent;
    if (parent->next == parent)
      parent->next = child;
    else
      parent->next->prev = parent;
  } else if (parent->next->prev == child) {
    /* parent is a right node */
    parent->next->prev = parent;

    assert(parent->prev->child->next == child);
    parent->prev->child->next = parent;
  } else {
    /* parent is a left node */
    assert(parent->prev->next == child);
    parent->prev->next = parent;

    assert(parent->next->prev->child == child);
    parent->next->prev->child = parent;
  }

  assert((*root_p)->prev != child);
  if ((*root_p)->prev == parent)
    (*root_p)->prev = child;

  if (parent->child == parent) {
    /* child is a left child */
    parent->child = child;
    if ((*root_p)->prev == child) {
      child->next = parent;
    } else {
      assert(child->next->prev == child);
      child->next->prev = parent;
    }
    if (child->prev == child) {
      child->prev = parent;
    } else {
      assert(child->prev->next == parent);
      child->prev->next = child;
    }
    /* FIXME fixup prev to point to me, carefully */
  } else {
    /* child is a right child */
    assert(child->prev == child);
    child->prev = parent;

    assert(parent->child->next == parent);
    parent->child->next = child;

    if ((*root_p)->prev != child) {
      assert(child->next->prev == parent);
      child->next->prev = child;
    }
  }

  if (child->child != NULL) {
    if (child->child == (*root_p)->prev) {
      assert(child->child->next == parent);
      child->child->next = child;
    } else {
      assert(child->child->next->prev == parent);
      child->child->next->prev = child;
    }
  }

  return true;
}

static bool io_timer_bubble_up(struct io_timer **root_p, struct io_timer *t) {
  bool ret = false;
  struct io_timer *parent;

  do {
    if (t == *root_p)
      break;
    else if (t == (*root_p)->prev)
      parent = t->next;
    else if (t->next->prev != t)
      parent = t->next->prev;
    else
      parent = t->prev;
  } while (io_timer_swap_parent_child(root_p, parent, t) && (ret = true));

  return ret;
}

static bool io_timer_bubble_down(struct io_timer **root_p, struct io_timer *t) {
  bool ret = false;
  struct io_timer *child;

  do {
    if (t->child == NULL)
      break;
    else if (t->child == (*root_p)->prev)
      child = t->child;
    else {
      unsigned long remaining;
      remaining = io_timer_remaining(t->child, &t->child->next->time);
      if (remaining == 0 || remaining < t->child->next->duration_ns)
        child = t->child;
      else
        child = t->child->next;
    }
  } while (io_timer_swap_parent_child(root_p, t, child) && (ret = true));

  return ret;
}

static int io_timer_set(struct event_loop *ev, struct io_callback *cb,
                        struct io_timer *timer, unsigned long duration_ns) {
  int ret;

  timer->cb = cb;
  timer->duration_ns = duration_ns;

  ret = clock_gettime(CLOCK_MONOTONIC, &timer->time);
  if (ret) {
    ret = -errno;
    return ret;
  }

  if (timer->prev != NULL) {
    /* The timer is already in the heap, try bubbling down */
    if (io_timer_bubble_down(&ev->timer, timer))
      return 0;
  } else {
    /* The timer is not already in the heap, add it */
    timer->child = NULL;
    timer->next = NULL;

    if (ev->timer == NULL)
      ev->timer = timer;
    else if (ev->timer->prev->next == NULL) {
      /*
       * The last node is either the root or a right child, so we're
       * creating a left child
       */
      struct io_timer *parent = ev->timer->prev->prev->next;
      if (parent == NULL)
        parent = ev->timer;

      timer->prev = ev->timer->prev;
      timer->next = parent;

      assert(parent->child == NULL);
      parent->child = timer;
      ev->timer->prev->next = timer;
    } else {
      /* We're creating a right child */
      timer->prev = ev->timer->prev->next;
      ev->timer->prev->next = timer;
    }

    ev->timer->prev = timer;
  }

  io_timer_bubble_up(&ev->timer, timer);

  return 0;
}

static void io_timer_cancel(struct event_loop *ev, struct io_timer *timer) {
  struct io_timer *replacement;
  bool bubble_down_only = false;
  assert(ev->timer != NULL && timer->prev != NULL);

  replacement = ev->timer->prev;
  if (replacement == ev->timer) {
    /* root node */
    assert(replacement == timer);
    ev->timer = NULL;
    bubble_down_only = true;
  } else if (replacement->next == NULL) {
    /* right node */
    ev->timer->prev = replacement->prev->child;
    ev->timer->prev->next = replacement->prev;
  } else {
    /* left node */
    ev->timer->prev = replacement->prev;
    assert(replacement->next->child == replacement);
    replacement->next->child = NULL;
    assert(replacement->prev->next == replacement);
    replacement->prev->next = NULL;
  }

  if (timer != replacement) {
    replacement->child = timer->child;
    replacement->prev = timer->prev;
    replacement->next = timer->next;

    if (ev->timer == timer) {
      /* root */
      ev->timer = replacement;
      if (ev->timer->prev != timer) {
        assert(replacement->next->prev == timer);
        replacement->next->prev = replacement;
      }
    } else if (replacement->prev->next == timer) {
      struct io_timer *parent;
      /* left node */
      replacement->prev->next = replacement;
      if (ev->timer->prev == timer)
        parent = replacement->next;
      else
        parent = replacement->next->prev;
      assert(parent->child == timer);
      parent->child = replacement;
    } else {
      /* right node */
      assert(replacement->prev->child->next == timer);
      replacement->prev->child->next = replacement;
      if (ev->timer->prev != timer) {
        assert(replacement->next->prev == timer);
        replacement->next->prev = replacement;
      }
    }

    if (ev->timer->prev == timer)
      ev->timer->prev = replacement;
    else if (replacement->child != NULL) {
      if (ev->timer->prev == replacement->child) {
        assert(replacement->child->next == timer);
        replacement->child->next = replacement;
      } else {
        assert(replacement->child->next->prev == timer);
        replacement->child->next->prev = replacement;
      }
    }
  }

  if (bubble_down_only || !io_timer_bubble_up(&ev->timer, replacement))
    io_timer_bubble_down(&ev->timer, replacement);

  /* Mark timer as not in the heap */
  timer->prev = NULL;
}


static void io_terminate(struct event_loop *ev, int err) {
  if (ev->terminated) {
    if (err)
      log_error(err, "while terminating");
    return;
  }

  if (err)
    log_error(err, "terminating");

  ev->terminated = true;

  for (size_t i = 0; i < ev->n_fds; ++i) {
    io_dispatch_callback_by_index(ev, POLLIN, i, &(int) { -EINTR });
    io_dispatch_callback_by_index(ev, POLLOUT, i, &(int) { -EINTR });
  }

  if (ev->timer) {
    int status = -EINTR;
    struct io_timer *timer = ev->timer;
    ev->timer = NULL;
    io_dispatch(ev, timer->cb, &status);
  }
}


static int io_socket(struct event_loop *ev, io_fd_t *fd,
                     sa_family_t domain, int type, int protocol) {
  int ret;

  ret = socket(domain, type, protocol);
  if (ret < 0)
    return -errno;

  return io_make_fd(ev, fd, ret);
}

static int io_connect(struct event_loop *ev, struct io_callback *cb,
                      void *extra,
                      io_fd_t socket, const struct sockaddr *address,
                      socklen_t address_len) {
  int ret;

  if (extra == NULL) {
    ret = connect(io_raw_fd(ev, socket), address, address_len);
    if (ret)
      ret = -errno;
    if (ret == -EINPROGRESS || ret == -EINTR) {
      ret = -EINPROGRESS;
      io_register_write_callback(ev, socket, cb);
    }
  } else if ((ret = *(int *) extra) == -EAGAIN) {
    int socket_raw_fd;
    struct sockaddr_storage ss;

    socket_raw_fd = io_raw_fd(ev, socket);

    ret = getpeername(socket_raw_fd,
                      (struct sockaddr *) &ss, &(socklen_t) { sizeof ss });
    if (ret)
      ret = -errno;
    if (ret == -ENOTCONN) {
      int ret2;
      socklen_t optlen;

      optlen = sizeof ret;
      ret2 = getsockopt(socket_raw_fd, SOL_SOCKET, SO_ERROR, &ret, &optlen);
      if (ret2 == 0)
        ret = -ret;
      else {
        ret = -errno;
        if (ret == -ENOPROTOOPT) {
          /* Try to get the return value from error slippage */
          ret = (read(socket_raw_fd, &(char[1]) { 0 }, 1) < 0);
          if (ret)
            ret = -errno;
          if (!ret || ret == -EINTR || ret == -EAGAIN || ret == -EWOULDBLOCK)
            ret = -ENOTCONN;
        }
      }
    }
  }
  return ret;
}


static int parse_addr(struct sockaddr_storage *ss,
                      const struct config_addr *addr) {
  void *parsed_addr_p;
  in_port_t port;
  int ret;

  port = htons(config_port);

  memset(ss, 0, sizeof *ss);
  switch (addr->af) {
  case AF_INET:
    parsed_addr_p = &((struct sockaddr_in *) ss)->sin_addr;
    ((struct sockaddr_in *) ss)->sin_port = port;
    break;
  case AF_INET6:
    parsed_addr_p = &((struct sockaddr_in6 *) ss)->sin6_addr;
    ((struct sockaddr_in6 *) ss)->sin6_port = port;
    break;
  default:
    return -EAFNOSUPPORT;
  }

  ret = inet_pton(addr->af, addr->addr, parsed_addr_p);
  if (ret == 1) {
    ss->ss_family = addr->af;
    return 0;
  } else if (ret == 0)
    return -EINVAL;
  else
    return -errno;
}


#define SM_CASE(x) sm_case_helper_(__LINE__, x)
#define sm_case_helper_(line, x) sm_case_helper2_(line, x)
#define sm_case_helper2_(line, x)                       \
  if (0) {                                              \
  case x:                                               \
    goto label__##line##x##__;                          \
  } else label__##line##x##__


/*
 * According to the C spec, we can only read lock-free atomic
 * variables in signal handlers
 */
#if ATOMIC_INT_LOCK_FREE == 2
atomic_int global_sighand_pipe_write_fd, global_last_signal = 0;
static int get_last_signal() {
  /* SYNCHRONIZES WITH fence in set_last_signal */
  atomic_thread_fence(memory_order_acquire);
  return atomic_load_explicit(&global_last_signal, memory_order_relaxed);
}
static void set_last_signal(int sig) {
  atomic_store_explicit(&global_last_signal, sig, memory_order_relaxed);
  /* SYNCHRONIZES WITH fence in get_last_signal */
  atomic_thread_fence(memory_order_release);
}
static void set_sighand_fd(int fd) {
  atomic_store_explicit(&global_sighand_pipe_write_fd, fd,
                        memory_order_relaxed);
}
static bool close_sighand_fd() {
  int fd = atomic_exchange_explicit(&global_sighand_pipe_write_fd, -1,
                                    memory_order_relaxed);
  if (fd >= 0) {
    close(fd);
    return true;
  } else
    return false;
}
#else
#error "signal handler not supported on this platform"
#endif

static void sighand(int sig) {
  /*
   * Reset the signal handler so that a subsequent signal will
   * automatically kill the process
   */
  signal(sig, SIG_DFL);
  set_last_signal(sig);
  if (!close_sighand_fd())
    raise(sig);
}

enum io_sighand_state { IO_SIGHAND_STATE_START, IO_SIGHAND_STATE_SIGNALED };
struct io_sighand_closure {
  struct io_callback cb;
  io_fd_t pipe_read_fd;
};

static int io_sighand_sm(struct event_loop *ev,
                         struct io_sighand_closure *c,
                         enum io_sighand_state state,
                         void *extra) {
  switch (state) {
    int ret;

  case IO_SIGHAND_STATE_START:

    ret = -ENOMEM;
    c = malloc(sizeof *c);
    if (c == NULL)
      goto out;

    {
      int pipefds[2];
      ret = pipe(pipefds);
      if (ret) {
        ret = -errno;
        goto out;
      }

      ret = fcntl(pipefds[1], F_GETFD);
      if (ret < 0) {
        ret = -errno;
        goto out;
      }
      ret = fcntl(pipefds[1], F_SETFD, ret | FD_CLOEXEC);
      if (ret) {
        ret = -errno;
        goto out;
      }
      set_sighand_fd(pipefds[1]);

      ret = io_make_fd(ev, &c->pipe_read_fd, pipefds[0]);
      if (ret)
        goto out_close_write_fd;
    }

    ret = (signal(SIGINT, &sighand) == SIG_ERR);
    if (ret) {
      ret = -errno;
      goto out_close_fds;
    }

    ret = (signal(SIGTERM, &sighand) == SIG_ERR);
    if (ret) {
      ret = -errno;
      goto out_reset_sigint;
    }

    c->cb = (struct io_callback) { .tag = IO_SIGHAND_SIGNALED };
    io_register_read_callback(ev, c->pipe_read_fd, &c->cb);
    return 0;

  SM_CASE(IO_SIGHAND_STATE_SIGNALED):
    ret = *(int *) extra;
    if (ret == -EAGAIN || (ret == -EINTR && ev->terminated))
      ret = 0;

    signal(SIGTERM, SIG_DFL);
  out_reset_sigint:
    signal(SIGINT, SIG_DFL);

  out_close_fds:
    io_close(ev, c->pipe_read_fd);
  out_close_write_fd:
    close_sighand_fd();

  out:
    free(c);
    if (ret)
      io_terminate(ev, -ret);
    return ret;

  }
  assert(0);
}

static void io_sighand_start(struct event_loop *ev) {
  io_sighand_sm(ev, NULL, IO_SIGHAND_STATE_START, NULL);
}

static void io_sighand_signaled(struct event_loop *ev,
                                struct io_callback *cb,
                                void *extra) {
  io_sighand_sm(ev, (struct io_sighand_closure *) cb,
                IO_SIGHAND_STATE_SIGNALED, extra);
}


enum io_net_conn_state {
  IO_NET_CONN_STATE_START,
  IO_NET_CONN_STATE_TIMER_FIRED,
  IO_NET_CONN_STATE_HAPPY_EYEBALLS
};
struct io_net_conn_closure {
  struct io_callback cb;
  struct io_happy_eyeballs_closure *happy_eyeballs_list;
  struct io_timer timer;
  size_t i;
  io_fd_t fd;
  bool timer_set;
};

static void io_net_conn_happy_eyeballs(struct event_loop *ev,
                                       struct io_net_conn_closure *c,
                                       void *extra);

enum io_happy_eyeballs_state {
  IO_HAPPY_EYEBALLS_STATE_START,
  IO_HAPPY_EYEBALLS_STATE_CONNECT,
  IO_HAPPY_EYEBALLS_STATE_CANCEL
};
struct io_happy_eyeballs_closure {
  struct io_callback cb;
  struct io_happy_eyeballs_closure *next, **prev;
  struct io_net_conn_closure *conn;
  struct sockaddr_storage ss;
  io_fd_t fd;
};

static int io_happy_eyeballs_sm(struct event_loop *ev,
                                struct io_happy_eyeballs_closure *c,
                                enum io_happy_eyeballs_state state,
                                void *extra) {
  switch (state) {
    struct io_net_conn_closure *conn;
    int ret;

  case IO_HAPPY_EYEBALLS_STATE_START:

    conn = extra;

    c = malloc(sizeof *c);
    if (c == NULL)
      return -ENOMEM;
    c->conn = conn;

    c->next = conn->happy_eyeballs_list;
    c->prev = &conn->happy_eyeballs_list;
    if (c->next)
      c->next->prev = &c->next;
    *c->prev = c;

    ret = parse_addr(&c->ss, &config_addrs[c->conn->i]);
    if (ret < 0)
      goto out_free;

    ret = io_socket(ev, &c->fd, c->ss.ss_family, SOCK_STREAM, 0);
    if (ret < 0)
      goto out_free;

    c->cb = (struct io_callback) { .tag = IO_HAPPY_EYEBALLS_CONNECT };

    extra = NULL;
  SM_CASE(IO_HAPPY_EYEBALLS_STATE_CONNECT):
    ret = io_connect(ev, &c->cb, extra,
                     c->fd, (struct sockaddr *) &c->ss, sizeof c->ss);
    if (ret == -EINPROGRESS)
      return ret;

    if (ret == 0)
      c->conn->fd = c->fd;
    else {
      if (0) SM_CASE(IO_HAPPY_EYEBALLS_STATE_CANCEL):
        ret = -ECANCELED;
      /* We did not transmit any data so this will not block */
      io_close(ev, c->fd);
    }

  out_free:
    if (c != NULL) {
      conn = c->conn;
      if (c->next)
        c->next->prev = c->prev;
      *c->prev = c->next;
    }
    free(c);

    return ret;

  }
  assert(0);
}

static int io_happy_eyeballs_start(struct event_loop *ev,
                                   struct io_net_conn_closure *conn) {
  return io_happy_eyeballs_sm(ev, NULL, IO_HAPPY_EYEBALLS_STATE_START, conn);
}

static void io_happy_eyeballs_connect(struct event_loop *ev,
                                      struct io_callback *cb,
                                      void *extra) {
  struct io_happy_eyeballs_closure *c = (struct io_happy_eyeballs_closure *) cb;
  struct io_net_conn_closure *conn = c->conn;
  int ret;

  ret = io_happy_eyeballs_sm(ev, c, IO_HAPPY_EYEBALLS_STATE_CONNECT, extra);
  io_net_conn_happy_eyeballs(ev, conn, &ret);
}

static void io_happy_eyeballs_cancel(struct event_loop *ev,
                                     struct io_happy_eyeballs_closure *c) {
  io_happy_eyeballs_sm(ev, c, IO_HAPPY_EYEBALLS_STATE_CANCEL, NULL);
}


static int io_net_conn_sm(struct event_loop *ev,
                          struct io_net_conn_closure *c,
                          enum io_net_conn_state state,
                          void *extra) {
  switch (state) {
    int ret;

  case IO_NET_CONN_STATE_START:

    ret = -ENOMEM;
    c = malloc(sizeof *c);
    if (c == NULL)
      goto out;
    c->cb = (struct io_callback) { .tag = IO_NET_CONN_TIMEOUT };

    ret = -EDESTADDRREQ;
    c->happy_eyeballs_list = NULL;
    c->timer_set = false;
    io_timer_init(&c->timer);

    for (c->i = 0;
         c->i < sizeof config_addrs / sizeof *config_addrs && !ev->terminated;
         ++c->i) {
      /* Reset the timer to 250ms */
      ret = io_timer_set(ev, &c->cb, &c->timer, 250000000);
      c->timer_set = (ret == 0);

      ret = io_happy_eyeballs_start(ev, c);

      if (ret == -EINPROGRESS)
        if (c->timer_set)
          return ret;
      /* FIXME on !c->timer_set we should probably defer to next event loop cycle */

      if (ret == -EAGAIN && c->happy_eyeballs_list != NULL) {
        /* We'll try again when another socket finishes */
        --c->i;
        return 0;
      }

      if (0) case IO_NET_CONN_STATE_HAPPY_EYEBALLS:
        ret = *(int *) extra;
      if (ret == -EINPROGRESS)
        return ret;

      if (ret == 0)
        break;

      if (0) case IO_NET_CONN_STATE_TIMER_FIRED:
        ret = *(int *) extra;
    }
    /* Cancel the timer */
    io_timer_cancel(ev, &c->timer);

    if (ret == 0) {
      while (c->happy_eyeballs_list)
        io_happy_eyeballs_cancel(ev, c->happy_eyeballs_list);
    } else if (c->happy_eyeballs_list != NULL)
      return -EINPROGRESS;
    else
      goto out;

    /* FIXME implement the protocol here */
    fprintf(stderr, "Dummy connection opened\n");

    /*
     * Make sure this won't be a blocking operation - it isn't right
     * now because we're not sending any data, but once the protocol
     * is implemented it might be
     */
    io_close(ev, c->fd);
  out:
    free(c);
    if (!ev->terminated)
      io_terminate(ev, -ret);
    return ret;

  }
  assert(0);
}

static void io_net_conn_start(struct event_loop *ev) {
  io_net_conn_sm(ev, NULL, IO_NET_CONN_STATE_START, NULL);
}

static void io_net_conn_timeout(struct event_loop *ev,
                                struct io_callback *cb,
                                void *extra) {
  io_net_conn_sm(ev, (struct io_net_conn_closure *) cb,
                 IO_NET_CONN_STATE_TIMER_FIRED, extra);
}

static void io_net_conn_happy_eyeballs(struct event_loop *ev,
                                       struct io_net_conn_closure *c,
                                       void *extra) {
  io_net_conn_sm(ev, c, IO_NET_CONN_STATE_HAPPY_EYEBALLS, extra);
}


static void io_dispatch(struct event_loop *ev, struct io_callback *cb,
                        void *extra) {
  switch (cb->tag) {
  case IO_SIGHAND_SIGNALED:
    io_sighand_signaled(ev, cb, extra);
    break;
  case IO_NET_CONN_TIMEOUT:
    io_net_conn_timeout(ev, cb, extra);
    break;
  case IO_HAPPY_EYEBALLS_CONNECT:
    io_happy_eyeballs_connect(ev, cb, extra);
    break;
  }
}


static int run() {
  struct event_loop ev;
  int ret;

  ret = event_loop_init(&ev);
  if (ret) {
    log_error(-ret, "event_loop_init");
    return ret;
  }

  io_sighand_start(&ev);
  io_net_conn_start(&ev);

  while (ev.n_fds > 0 || ev.timer != NULL) {
    struct timespec time;
    int timeout = -1;

    if (ev.timer != NULL) {
      unsigned long timer_remaining;
      ret = clock_gettime(CLOCK_MONOTONIC, &time);
      if (!ret)
        timer_remaining = io_timer_remaining(ev.timer, &time);
      if (ret || timer_remaining == 0) {
        do {
          int ret2 = ret || -ETIME;
          struct io_timer *timer = ev.timer;

          io_timer_cancel(&ev, timer);
          io_dispatch(&ev, timer->cb, &ret2);
        } while (ev.timer != NULL && (ret || io_timer_remaining(ev.timer, &time) == 0));
        continue;
      }
      if ((timer_remaining - 1) / 1000000ul + 1 > INT_MAX)
        timeout = INT_MAX;
      else
        timeout = (int) ((timer_remaining - 1) / 1000000ul + 1);
    }

    ret = poll(ev.pollfds, ev.n_fds, timeout);
    if (ret < 0) {
      ret = -errno;
      if (ret != -EAGAIN && ret != -EINTR) {
        log_error(-ret, "poll");
        /* 
         * FIXME we might want to try to do a bit more cleanup here?
         * Signals at least?
         */
        return ret;
      }
    }

    for (size_t i = 0; i < ev.n_fds && ret > 0; ++i) {
      if (ev.pollfds[i].revents == 0)
        continue;
      --ret;

      ev.pollfds[i].events &= (short) ~ev.pollfds[i].revents;
      if (!ev.pollfds[i].events && ev.pollfds[i].fd >= 0)
        ev.pollfds[i].fd = -ev.pollfds[i].fd - 1;
      if (ev.pollfds[i].revents & (POLLIN | POLLERR | POLLHUP))
        io_dispatch_callback_by_index(&ev, POLLIN, i, &(int) { -EAGAIN });
      if (ev.pollfds[i].revents & (POLLOUT | POLLERR | POLLHUP))
        io_dispatch_callback_by_index(&ev, POLLOUT, i, &(int) { -EAGAIN });
      if (ev.pollfds[i].revents & POLLNVAL && ev.pollfds[i].fd >= 0) {
        io_dispatch_callback_by_index(&ev, POLLIN, i, &(int) { -EBADF });
        io_dispatch_callback_by_index(&ev, POLLOUT, i, &(int) { -EBADF });
        io_close(&ev, ev.fds[i]);
      }
    }

    while (ev.close_fd != NULL) {
      size_t i = (size_t) (ev.close_fd - ev.fds);
      ev.close_fd = *ev.close_fd;
      while (ev.n_fds && ev.pollfds[ev.n_fds - 1].events & POLLNVAL)
        --ev.n_fds;
      if (i < ev.n_fds) {
        --ev.n_fds;
        ev.fds[i] = ev.fds[ev.n_fds];
        ev.pollfds[i] = ev.pollfds[ev.n_fds];
        ((struct io_fd *) ev.fds[i])->index = i;
      }
    }

    if (ev.n_fds < ev.alloc_size / 4) {
      void *new_mem;
      ev.alloc_size /= 2;

      new_mem = realloc(ev.fds, sizeof *ev.fds * ev.alloc_size);
      if (new_mem != NULL)
        ev.fds = new_mem;

      new_mem = realloc(ev.pollfds, sizeof *ev.pollfds * ev.alloc_size);
      if (new_mem != NULL)
        ev.pollfds = new_mem;
    }
  }

  event_loop_cleanup(&ev);
  return 0;
}

int main() {
  int ret, sig;
  ret = run();
  sig = get_last_signal();
  if (sig)
    raise(sig);
  return ret ? EXIT_FAILURE : EXIT_SUCCESS;
}
