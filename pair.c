#define _GNU_SOURCE

#include <stdlib.h>
#include <stdbool.h>

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>

#include <sys/types.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include "log.h"

#include "config.h"

struct io_callback {
  enum { IO_NET_CONN_TIMEOUT, IO_HAPPY_EYEBALLS_CONNECT } tag;
};

typedef struct io_fd {
  size_t index;
  struct io_callback *pollin_cb, *pollout_cb;
} *io_fd_t;

struct event_loop {
  struct io_fd **fds;
  struct pollfd *pollfds;
  struct io_timer *timer;
  size_t n_fds, alloc_size;
  bool terminated;
};

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

  ev->timer = NULL;
  ev->n_fds = 0;
  ev->terminated = false;

  return 0;
}


static int io_raw_fd(struct event_loop *ev, io_fd_t fd) {
  return ev->pollfds[fd->index].fd;
}

static int io_make_fd(struct event_loop *ev, io_fd_t *io_fd, int raw_fd) {
  int ret = -ENOMEM;

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
  ev->pollfds[(*io_fd)->index] = (struct pollfd) { .fd = raw_fd };
  return 0;

out:
  close(raw_fd);
  return ret;
}

static void io_close(struct event_loop *ev, io_fd_t fd) {
  /* FIXME cancel any remaining IO callbacks? */

  /* Don't worry about errors on close */
  close(io_raw_fd(ev, fd));

  --ev->n_fds;
  ev->fds[fd->index] = ev->fds[ev->n_fds];
  ev->pollfds[fd->index] = ev->pollfds[ev->n_fds];
  ev->fds[fd->index]->index = fd->index;
  free(fd);

  if (ev->n_fds < ev->alloc_size / 4) {
    void *new_mem;
    size_t new_alloc_size = ev->alloc_size / 2;

    new_mem = realloc(ev->fds, sizeof *ev->fds * new_alloc_size);
    if (new_mem == NULL)
      return;
    ev->alloc_size = new_alloc_size;
    ev->fds = new_mem;

    new_mem = realloc(ev->pollfds, sizeof *ev->pollfds * new_alloc_size);
    if (new_mem == NULL)
      return;
    ev->pollfds = new_mem;
  }
}

static void io_register_write_callback(struct event_loop *ev, io_fd_t fd,
                                       struct io_callback *cb) {
  ev->pollfds[fd->index].events |= POLLOUT;
  fd->pollout_cb = cb;
}


struct io_timer {
  struct timespec time;
  struct io_callback *cb;
  unsigned long duration_ns;
};

static void io_timer_cancel(struct event_loop *ev, struct io_timer *timer) {
  /* FIXME allow multiple timers */
  assert(ev->timer == NULL || ev->timer == timer);
  ev->timer = NULL;
}

static int io_timer_set(struct event_loop *ev, struct io_callback *cb,
                        struct io_timer *timer, unsigned long duration_ns) {
  int ret;

  io_timer_cancel(ev, timer);

  timer->cb = cb;
  timer->duration_ns = duration_ns;

  ret = clock_gettime(CLOCK_MONOTONIC, &timer->time);
  if (ret) {
    ret = -errno;
    return ret;
  }

  /* FIXME allow multiple timers */
  assert(ev->timer == NULL || ev->timer == timer);
  ev->timer = timer;

  return ret;
}

static unsigned long io_timer_remaining(struct io_timer *timer,
                                        struct timespec *time) {
  unsigned long ret;

  assert(timer->base_time.tv_nsec >= 0 && timer->base_time.tv_nsec < 1000000000);
  assert(time->tv_nsec >= 0 && time->tv_nsec < 1000000000);

  /*
   * Note: this mess calculates
   * (base.tv_sec - time.tv_sec) * 10^9 + (base.tv_nsec - time.tv_nsec) + duration_ns
   * clamped to [LONG_MIN, LONG_MAX], without integer overflows, regardless of
   * the size or signedness of time_t
   */

  const unsigned long sec = 1000000000ul;

  if (timer->base_time.tv_sec > time->tv_sec ||
      (timer->base_time.tv_sec == time->tv_sec &&
       timer->base_time.tv_nsec > time->tv_nsec)) {
    const unsigned long bound = ULONG_MAX / sec + 1;

    ret = timer->base_time.tv_nsec - time->tv_nsec;

    if (timer->base_time.tv_sec <= 0 || time->tv_sec >= 0) {
      if (timer->base_time.tv_sec - time->tv_sec > bound)
        return ULONG_MAX;
    } else {
      if (bound + time->tv_sec > bound ||
          timer->base_time.tv_sec > bound + time->tv_sec)
        return ULONG_MAX;
    }
    ret += (unsigned long) (timer->base_time.tv_sec - time->tv_sec) * sec;
  }

  const long upper_bound = LONG_MAX / sec + 1,
    lower_bound = LONG_MIN / sec - 2;

  const long duration_sec = duration / sec;

  if (timer->base_time.tv_sec >= 0 && time->tv_sec <= 0) {
    /* 
     * base_time.tv_sec + (-time.tv_sec) + duration_sec is adding
     * three positives - therefore if any step overflows LONG_MAX, the
     * whole calculation will overflow
     */
    if (timer->base_time.tv_sec > upper_bound - duration_sec)
      return LONG_MAX;
    if (time->tv_sec < (long) timer->base_time.tv_sec + duration_sec - upper_bound)
      return LONG_MAX;
    ret = ((long) timer->base_time.tv_sec + duration_sec) - (long) time->tv_sec;
  } else if (timer->base_time.tv_sec <= 0 && time->tv_sec >= 0) {
    /*
     * Neither of the computations on either side will overflow,
     * because the addends have opposite signs
     */
    if (timer->base_time.tv_sec + duration_sec < lower_bound + time->tv_sec)
      return LONG_MIN;
    ret = (long) (timer->base_time.tv_sec + duration_sec - time->tv_sec);
  } else {
    if (timer->base_time.tv_sec - time->tv_sec > upper_bound - duration)
      return LONG_MAX;
    
  }

  if (timer->base_time.tv_sec > time->sec) {
    const long overflow_check = LONG_MAX / SEC + 1;
    if (time->sec >= 0) {
      if (timer->base_time.tv_sec - time->tv_sec > overflow_check)
        return LONG_MAX;
    } else {
      if (timer->base_time.tv_sec > overflow_check + time->tv_sec)
        return LONG_MAX;
    }
    ret = ((long) (timer->base_time.tv_sec - time->tv_sec) - 1) * SEC;

    if (timer->base_time.tv_nsec - time->tv_nsec > LONG_MAX - ret)
      return LONG_MAX;
    ret += timer->base_time.tv_nsec - time->tv_nsec;
    if (ret > LONG_MAX - 1*SEC)
      return LONG_MAX;
    ret += 1*SEC;
    if (ret > LONG_MAX - timer->duration_ns)
      return LONG_MAX;
    ret += timer->duration_ns;
  } else {
    
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
  } else {
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
      if (ret2) {
        ret = -errno;
        if (ret == -ENOPROTOOPT) {
          /* Try to get the return value from error slippage */
          ret = read(socket_raw_fd, &(char[1]) { 0 }, 1);
          if (ret < 0)
            ret = -errno;
          if (ret >= 0 || ret == -EINTR || ret == -EAGAIN || ret == -EWOULDBLOCK)
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
  IO_HAPPY_EYEBALLS_STATE_CONNECT
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

  default: assert(0);
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

    /* FIXME remember to set O_CLOEXEC and O_NONBLOCK here */
    ret = io_socket(ev, &c->fd, c->ss.ss_family, SOCK_STREAM, 0);
    if (ret < 0)
      goto out_free;

    c->cb = (struct io_callback) { .tag = IO_HAPPY_EYEBALLS_CONNECT };

    extra = NULL;
  case IO_HAPPY_EYEBALLS_STATE_CONNECT:
    ret = io_connect(ev, &c->cb, extra,
                     c->fd, (struct sockaddr *) &c->ss, sizeof c->ss);
    if (ret == -EINPROGRESS)
      return ret;

    if (ret == 0)
      c->conn->fd = c->fd;
    else
      /* FIXME make sure this won't somehow block */
      io_close(ev, c->fd);

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
}

static int io_happy_eyeballs_start(struct event_loop *ev,
                                   struct io_net_conn_closure *conn) {
  int ret;

  ret = io_happy_eyeballs_sm(ev, NULL, IO_HAPPY_EYEBALLS_STATE_START, conn);
  if (ret == -EINPROGRESS)
    ret = 0;
  return ret;
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


static int io_net_conn_sm(struct event_loop *ev,
                          struct io_net_conn_closure *c,
                          enum io_net_conn_state state,
                          void *extra) {
  switch (state) {
    int ret;

  default: assert(0);
  case IO_NET_CONN_STATE_START:

    ret = -ENOMEM;
    c = malloc(sizeof *c);
    if (c == NULL)
      goto out;
    c->cb = (struct io_callback) { .tag = IO_NET_CONN_TIMEOUT };

    ret = -EDESTADDRREQ;
    c->happy_eyeballs_list = NULL;
    c->timer_set = false;
    for (c->i = 0; c->i < sizeof config_addrs / sizeof *config_addrs; ++c->i) {
      /* Reset the timer to 250ms */
      ret = io_timer_set(ev, &c->cb, &c->timer, 250000000);
      c->timer_set = (ret == 0);

      do
        ret = io_happy_eyeballs_start(ev, c);
      while (ret == -EINTR);

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
        ret = -ETIME;
    }
    /* Cancel the timer */
    io_timer_cancel(ev, &c->timer);

    if (ret == 0) {
      fixme clean up all the threads;
    } else if (c->happy_eyeballs_list != NULL)
      return -EINPROGRESS;
    else
      goto out;

    /* FIXME implement the protocol here */
    printf("Dummy connetion opened\n");

    /* FIXME make sure this won't be a blocking operation */
    io_close(ev, c->fd);
  out:
    free(c);
    log_error(-ret, "io_happy_eyeballs");
    /* FIXME log error, terminate... */
    return ret;

  }
}

static void io_net_conn_start(struct event_loop *ev) {
  io_net_conn_sm(ev, NULL, IO_NET_CONN_STATE_START, NULL);
}

static void io_net_conn_happy_eyeballs(struct event_loop *ev,
                                       struct io_net_conn_closure *c,
                                       void *extra) {
  io_net_conn_sm(ev, c, IO_NET_CONN_STATE_HAPPY_EYEBALLS, extra);
}


static int run() {
  struct event_loop ev;
  int ret;

  ret = event_loop_init(&ev);
  if (ret)
    return ret;

  io_net_conn_start(&ev);

  while (1) {
    struct timespec time;
    int timeout = -1;

    if (ev.timer != NULL) {
      unsigned long timer_remaining;
      ret = clock_gettime(CLOCK_MONOTONIC, &time);
      if (ret)
        /* FIXME cleanup, or maybe just fire all the timers? */
        return ret;
      timer_remaining = io_timer_remaining(&ev.timer, &time);
      if (timer_remaining == 0) {
        do {
          struct io_timer *timer;

          timer = ev.timer;
          ev.timer = NULL;
          io_dispatch(timer->cb, NULL);
        } while (ev.timer != NULL && io_timer_remaining(&ev.timer, &time) == 0);
        continue;
      }
      if ((timer_remaining - 1) / 1000000ul + 1 > INT_MAX)
        timeout = INT_MAX;
      else
        timeout = (timer_remaining - 1) / 1000000ul + 1;
    }

    ret = poll(ev.pollfds, ev.n_fds, timeout);
    if (ret < 0) {
      ret = -errno;
      if (ret != -EAGAIN && ret != -EINTR)
        /* FIXME log this error? */
        return ret;
    }

    for (size_t i = 0; i < ev.n_fds && ret > 0; ++i) {
      if (ev.pollfds[i].revents == 0)
        continue;
      --ret;
      if (ev.pollfds[i].revents & (POLLIN | POLLERR)) {
        ev.pollfds[i].events &= ~POLLIN;
        io_dispatch(ev.fds[i]->pollin_cb, &ev.pollfds[i].revents);
      }
      if (ev.pollfds[i].revents & (POLLOUT | POLLERR | POLLHUP)) {
        ev.pollfds[i].events &= ~POLLOUT;
        io_dispatch(ev.fds[i]->pollout_cb, &ev.pollfds[i].revents);
      }
      if (ev.pollfds[i].revents & POLLNVAL)
        io_close(ev.fds[i]);
    }
  }
}
