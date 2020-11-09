#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <string.h>

#include <unistd.h>

#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <linux/io_uring.h>

#include "config.h"


static void log_error(int err, const char *format, ...) {
  va_list ap;
  va_start(ap, format);
  flockfile(stderr);
  fprintf(stderr, "%s: ", program_invocation_short_name);
  if (format)
    vfprintf(stderr, format, ap);
  fprintf(stderr, "%s%s\n", format ? ": " : "", strerror(err));
  funlockfile(stderr);
  va_end(ap);
}


struct io_callback {
  enum {
    IO_LISTEN
  } tag;
  struct io_callback *prev, *next;
};

static bool io_callback_detached(struct io_callback *cb) {
  assert((cb->prev == NULL) == (cb->next == NULL));
  return cb->next == NULL;
}

static void io_callback_pop(struct io_callback **head_p,
                            struct io_callback *cb) {
  cb->next->prev = cb->prev;
  cb->prev->next = cb->next;
  if (*head_p == cb)
    *head_p = cb->next == cb ? NULL : cb->next;
  cb->next = cb->prev = NULL;
}

static struct io_callback *
io_callback_concat(struct io_callback *restrict cb1,
                   struct io_callback *restrict cb2) {
  struct io_callback *tmp;
  if (cb1 == NULL)
    return cb2;
  if (cb2 == NULL)
    return cb1;
  cb1->prev->next = cb2;
  cb2->prev->next = cb1;
  tmp = cb1->prev;
  cb1->prev = cb2->prev;
  cb2->prev = tmp;
  return cb1;
}

static void io_callback_push(struct io_callback **head_p,
                             struct io_callback *cb) {
  cb->prev = cb->next = cb;
  *head_p = io_callback_concat(*head_p, cb);
}

struct io_uring_desc {
  int fd;
  size_t sq_size, cq_size, sqes_size;
  unsigned char *sq_ring, *cq_ring;

  __u32 sq_n_entries, sq_mask, cq_n_entries, cq_mask;
  __u32 *sq_head_p, *sq_tail_p;
  __u32 *cq_head_p, *cq_tail_p;
  __u32 *sqes_buf;
  struct io_uring_sqe *sqes;
  struct io_uring_cqe *cqes_buf;

  struct io_callback *pending_ios, *retry_ios;
  __u32 sq_cached_head, sq_cached_tail, cq_cached_head, cq_cached_tail;

  sigset_t sigset;
  bool terminated;
};

/* FIXME this function is a mess */
static int create_io_uring_helper(struct io_uring_desc *d, bool destroy) {
  struct io_uring_params p = { 0 };
  int ret;

  if (destroy)
    goto out;

  d->pending_ios = d->retry_ios = NULL;
  d->sq_cached_head = d->sq_cached_tail =
    d->cq_cached_head = d->cq_cached_tail = 0;
  d->terminated = false;

  if ((d->fd = syscall(SYS_io_uring_setup, 4096, &p)) < 0)
    return -errno;

  /* We need IORING_FEAT_NODROP so that we don't lose BUFFER_SELECT responses */
  ret = -ENOTSUP;
  if (~p.features & IORING_FEAT_NODROP)
    goto out_close;

  d->sq_size = p.sq_off.array + p.sq_entries * sizeof *d->sqes_buf;
  d->cq_size = p.cq_off.cqes + p.cq_entries * sizeof *d->cqes_buf;
  d->sqes_size = p.sq_entries * sizeof (struct io_uring_sqe);

  if (p.features & IORING_FEAT_SINGLE_MMAP && d->cq_size > d->sq_size)
    d->sq_size = d->cq_size;

  if ((d->sq_ring = mmap(NULL, d->sq_size,
                         PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                         d->fd, IORING_OFF_SQ_RING)) == MAP_FAILED) {
    ret = -errno;
    goto out_close;
  }
  d->sqes_buf = (void *) (d->sq_ring + p.sq_off.array);
  d->sq_head_p = (void *) (d->sq_ring + p.sq_off.head);
  d->sq_tail_p = (void *) (d->sq_ring + p.sq_off.tail);

  if (p.features & IORING_FEAT_SINGLE_MMAP)
    d->cq_ring = d->sq_ring;
  else if ((d->cq_ring = mmap(NULL, d->cq_size,
                              PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                              d->fd, IORING_OFF_CQ_RING)) == MAP_FAILED) {
    ret = -errno;
    goto out_unmap_sq;
  }
  d->cqes_buf = (void *) (d->cq_ring + p.cq_off.cqes);
  d->cq_head_p = (void *) (d->cq_ring + p.cq_off.head);
  d->cq_tail_p = (void *) (d->cq_ring + p.cq_off.tail);

  if ((d->sqes = mmap(NULL, d->sqes_size,
                      PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                      d->fd, IORING_OFF_SQES)) == MAP_FAILED) {
    ret = -errno;
    goto out_munmap_cq;
  }

  d->sq_n_entries = p.sq_entries;
  d->sq_mask = *(__u32 *) (d->sq_ring + p.sq_off.ring_mask);
  d->cq_n_entries = p.cq_entries;
  d->cq_mask = *(__u32 *) (d->cq_ring + p.cq_off.ring_mask);

  /* Fill up the submission queue buf with indices */
  for (__u32 i = 0; i < d->sq_n_entries; ++i)
    d->sqes_buf[i] = i;

  return 0;

out:
  munmap(d->sqes, d->sqes_size);
out_munmap_cq:
  if (d->cq_ring != d->sq_ring)
    munmap(d->cq_ring, d->cq_size);
out_unmap_sq:
  munmap(d->sq_ring, d->sq_size);
out_close:
  close(d->fd);
  if (destroy)
    return 0;
  return ret;
}

static int create_io_uring(struct io_uring_desc *d) {
  return create_io_uring_helper(d, false);
}
static void destroy_io_uring(struct io_uring_desc *d) {
  create_io_uring_helper(d, true);
}

static int io_uring_submit_all(struct io_uring_desc *ring, bool wait) {
  int ret;

  ret = syscall(SYS_io_uring_enter, ring->fd,
                ring->sq_cached_tail - ring->sq_cached_head,
                wait ? 1 : 0, wait ? IORING_ENTER_GETEVENTS : 0,
                &ring->sigset, _NSIG / 8);
  if (ret < 0) {
    ret = -errno;
    if (ret == -EAGAIN || ret == -EINTR || ret == -EBUSY)
      ret = 0;
  }

  __atomic_load(ring->sq_head_p, &ring->sq_cached_head, __ATOMIC_ACQUIRE);
  return ret;
}

static __u32 io_n_free_sqes(struct io_uring_desc *ring) {
  return ring->sq_cached_head + ring->sq_n_entries - ring->sq_cached_tail;
}

static int io_submit_sqes(struct io_uring_desc *ring,
                          size_t n, struct io_uring_sqe sqes[static n]) {
  int ret;
  __u32 index, first_stride;
  bool retry;

  if (io_n_free_sqes(ring) < n)
    __atomic_load(ring->sq_head_p, &ring->sq_cached_head, __ATOMIC_ACQUIRE);
  if (io_n_free_sqes(ring) < n && ring->retry_ios != NULL) {
    ret = io_uring_submit_all(ring, false);
    if (ret < 0)
      return ret;
  }

  retry = io_n_free_sqes(ring) < n;
  for (size_t i = 0; i < n; ++i) {
    struct io_callback *cb = (void *) sqes[i].user_data;
    if (cb != NULL && io_callback_detached(cb))
      io_callback_push(retry ? &ring->retry_ios : &ring->pending_ios, cb);
  }
  if (retry)
    return -EAGAIN;

  index = ring->sq_cached_tail & ring->sq_mask;
  first_stride = ring->sq_n_entries - index;
  if (n < first_stride)
    first_stride = n;

  memcpy(ring->sqes + index, sqes, first_stride * sizeof *sqes);
  memcpy(ring->sqes, sqes + first_stride, (n - first_stride) * sizeof *sqes);

  ring->sq_cached_tail += n;
  /* RELEASE the entries to the kernel */
  __atomic_store(ring->sq_tail_p, &ring->sq_cached_tail, __ATOMIC_RELEASE);
  return n;
}


static int io_accept(struct io_uring_desc *ring, struct io_callback *cb,
                     int fd, struct sockaddr *addr, socklen_t *addrlen) {
  struct io_uring_sqe sqe = { 0 };

  sqe.opcode    = IORING_OP_ACCEPT;
  sqe.user_data = (__u64) (void *) cb;
  sqe.flags     = 0;            /* FIXME IOSQE_FIXED_FILE? */
  sqe.ioprio    = 0;
  sqe.fd        = fd;
  sqe.addr      = (__u64) addr;
  sqe.addr2     = (__u64) addrlen;
  sqe.accept_flags = SOCK_CLOEXEC;
  return io_submit_sqes(ring, 1, &sqe);
}

static int io_close(struct io_uring_desc *ring, int fd) {
  struct io_uring_sqe sqe = { 0 };

  sqe.opcode    = IORING_OP_CLOSE;
  sqe.user_data = (__u64) (void *) NULL;
  sqe.flags     = 0;            /* FIXME how to handle fixed FDs? */
  sqe.ioprio    = 0;
  sqe.fd        = fd;
  return io_submit_sqes(ring, 1, &sqe);
}

static int io_cancel(struct io_uring_desc *ring, struct io_callback *cb) {
  struct io_uring_sqe sqe = { 0 };

  sqe.opcode    = IORING_OP_ASYNC_CANCEL;
  sqe.user_data = (__u64) (void *) NULL;
  sqe.flags     = 0;
  sqe.ioprio    = 0;
  sqe.addr      = (__u64) (void *) cb;
  return io_submit_sqes(ring, 1, &sqe);
}

static int io_callback_dispatch(struct io_uring_desc *, struct io_callback *,
                                int res, void *extra);

static void terminate_all_ios(struct io_uring_desc *ring, int err) {
  struct io_callback *list, *cb;
  if (ring->terminated) {
    log_error(err, "while terminating");
    return;
  }

  log_error(err, "terminating");

  ring->terminated = true;

  /* First cancel all the outstanding ios */
  list = ring->pending_ios;
  if (list != NULL) {
    cb = list;
    do {
      io_cancel(ring, cb);
      cb = cb->next;
    } while (cb != list);
  }

  /* Now cancel all the unsubmitted ios */
  list = ring->retry_ios;
  ring->retry_ios = NULL;
  while (list != NULL) {
    cb = list;
    io_callback_pop(&list, cb);
    io_callback_dispatch(ring, cb, -ECANCELED, NULL);
  }
}


static int io_conn_start(struct io_uring_desc *, int ret);

enum io_listen_state { IO_LISTEN_STATE_START, IO_LISTEN_STATE_ACCEPT_RET };
struct io_listen_closure {
  struct io_callback cb;
  int fd;
};

static int io_listen_sm(struct io_uring_desc *ring,
                        struct io_listen_closure *c,
                        enum io_listen_state state, int ret) {
  switch (state) {
  default: assert(0);
  case IO_LISTEN_STATE_START:

    while (!ring->terminated) {
      ret = io_accept(ring, &c->cb, c->fd, NULL, NULL);
      if (ret < 0 && ret != -EAGAIN)
        break;
      return ret;

    case IO_LISTEN_STATE_ACCEPT_RET:
      switch (ret) {
      default:
        if (ret < 0)
          break;
        __attribute__((fallthrough));
      case -ECONNABORTED:
      case -EMFILE:
      case -ENFILE:
      case -ENOBUFS:
      case -ENOMEM:
      case -EPROTO:
      case -EPERM:
      case -ENOSR:
      case -ESOCKTNOSUPPORT:
      case -EPROTONOSUPPORT:
      case -ETIMEDOUT:
      case -ENETDOWN:
      case -ENOPROTOOPT:
      case -EHOSTDOWN:
      case -ENONET:
      case -EHOSTUNREACH:
      case -EOPNOTSUPP:
      case -ENETUNREACH:
        io_conn_start(ring, ret);
        __attribute__((fallthrough));
      case -ECANCELED:
      case -EAGAIN:
      case -EINTR:
        ret = 0;
        continue;
      }
      break;
    }

    assert(c->cb.prev == NULL);
    assert(c->cb.next == NULL);
    io_close(ring, c->fd);
    free(c);

    if (ret < 0) {
      log_error(-ret, "accepting connection");
      terminate_all_ios(ring, -ret);
    }
    return ret;
  }
}

static int io_listen_start(struct io_uring_desc *ring, int fd) {
  struct io_listen_closure *c;
  int ret;

  c = malloc(sizeof *c);
  if (c == NULL) {
    io_close(ring, fd);
    return -ENOMEM;
  }
  c->cb = (struct io_callback) { .tag = IO_LISTEN };
  c->fd = fd;

  ret = io_listen_sm(ring, c, IO_LISTEN_STATE_START, 0);
  if (ret == -EAGAIN)
    ret = 0;
  return ret;
}

static int io_listen_callback(struct io_uring_desc *ring,
                              struct io_callback *cb,
                              int res, void *extra) {
  (void) extra;
  return io_listen_sm(ring, (struct io_listen_closure *) cb,
                      IO_LISTEN_STATE_ACCEPT_RET, res);
}


enum io_conn_state { IO_CONN_STATE_START };

static int io_conn_sm(struct io_uring_desc *ring,
                      enum io_conn_state state, int ret) {
  switch (state) {
    int fd;

  default: assert(0);
  case IO_CONN_STATE_START:

    if (ret < 0) {
      log_error(-ret, "accepting new connection");
      return ret;
    }
    fd = ret;

    printf("Inside null connection state machine\n");
    io_close(ring, fd);

    return 0;
  }
}

static int io_conn_start(struct io_uring_desc *ring, int ret) {
  ret = io_conn_sm(ring, IO_CONN_STATE_START, ret);
  if (ret == -EAGAIN)
    ret = 0;
  return ret;
}


static int io_callback_dispatch(struct io_uring_desc *ring,
                                struct io_callback *cb,
                                int res, void *extra) {
  switch (cb->tag) {
  case IO_LISTEN:
    return io_listen_callback(ring, cb, res, extra);
  default:
    assert(0);
  }
}


static volatile sig_atomic_t terminating_from_signal = 0;
void sighand_terminate(int sig) {
  (void) sig;
  terminating_from_signal = 1;
}


static int create_tcp_listen_sock(const struct sockaddr *addr,
                                  socklen_t addrlen) {
  int sock, flag, ret;

  sock = socket(addr->sa_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (sock < 0)
    return -errno;

  if (addr->sa_family == AF_INET6) {
    flag = 1;
    ret = setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &flag, sizeof flag);
    if (ret) {
      ret = -errno;
      goto out;
    }
  }

  flag = 1;
  ret = setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof flag);
  if (ret) {
    ret = -errno;
    goto out;
  }

  ret = bind(sock, addr, addrlen);
  if (ret) {
    ret = -errno;
    goto out;
  }

  ret = listen(sock, SOMAXCONN);
  if (ret) {
    ret = -errno;
    goto out;
  }

  return sock;

out:
  close(sock);
  return ret;
}

static int run_server() {
  struct io_uring_desc ring;
  int ret, ipv4_sock, ipv6_sock;
  struct sockaddr_in ipv4_addr = { 0 };
  struct sockaddr_in6 ipv6_addr = { 0 };
  struct sigaction sigact = {
    .sa_handler = &sighand_terminate,
    .sa_flags = SA_RESETHAND
  };
  sigset_t blockset;

  ret = sigemptyset(&blockset);
  if (ret) {
    ret = -errno;
    log_error(-ret, "sigemptyset");
    return ret;
  }

  ret = sigaddset(&blockset, SIGINT);
  if (ret) {
    ret = -errno;
    log_error(-ret, "sigaddset(SIGINT)");
    return ret;
  }

  ret = sigaddset(&blockset, SIGTERM);
  if (ret) {
    ret = -errno;
    log_error(-ret, "sigaddset(SIGTERM)");
    return ret;
  }

  ret = sigprocmask(SIG_BLOCK, &blockset, &ring.sigset);
  if (ret) {
    ret = -errno;
    log_error(-ret, "sigprocmask");
    return ret;
  }

  ret = sigaction(SIGINT, &sigact, NULL);
  if (ret) {
    ret = -errno;
    log_error(-ret, "sigaction(SIGINT)");
    return ret;
  }

  ret = sigaction(SIGTERM, &sigact, NULL);
  if (ret) {
    ret = -errno;
    log_error(-ret, "sigaction(SIGTERM)");
    return ret;
  }

  ret = create_io_uring(&ring);
  if (ret < 0) {
    log_error(-ret, "create_io_uring");
    return ret;
  }

  ipv4_addr.sin_family = AF_INET;
  ipv4_addr.sin_port = htons(config_port);
  ipv4_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  ipv4_sock = create_tcp_listen_sock((struct sockaddr *) &ipv4_addr,
                                     sizeof ipv4_addr);
  if (ipv4_sock < 0)
    log_error(-ipv4_sock, "creating ipv4 tcp listen socket");

  ipv6_addr.sin6_family = AF_INET6;
  ipv6_addr.sin6_port = htons(config_port);
  memcpy(&ipv6_addr.sin6_addr, &in6addr_any, sizeof ipv6_addr.sin6_addr);
  ipv6_sock = create_tcp_listen_sock((struct sockaddr *) &ipv6_addr,
                                     sizeof ipv6_addr);
  if (ipv6_sock < 0)
    log_error(-ipv6_sock, "creating ipv6 tcp listen socket");

  if (ipv4_sock < 0 && ipv6_sock < 0)
    terminate_all_ios(&ring, ECANCELED);

  if (ipv4_sock >= 0)
    ret = io_listen_start(&ring, ipv4_sock);

  if (ipv6_sock >= 0)
    ret = io_listen_start(&ring, ipv6_sock);

  while (ring.pending_ios != NULL || ring.retry_ios != NULL) {
    struct io_callback *cb;

    ret = io_uring_submit_all(&ring, ring.retry_ios == NULL);
    if (ret < 0)
      terminate_all_ios(&ring, -ret);
    if (terminating_from_signal && !ring.terminated) {
      /*
       * Reset the signal mask so that a subsequent invocation (which
       * hits SIG_DFL, because of SA_RESETHAND) will immediately kill
       * the process
       */
      sigprocmask(SIG_SETMASK, &ring.sigset, NULL);
      terminate_all_ios(&ring, ECANCELED);
    }

    for (;;) {
      struct io_uring_cqe *cqe;
      __u32 cqe_res, flags;

      if (ring.cq_cached_head == ring.cq_cached_tail) {
        /* ACQUIRE some completions from the kernel */
        __atomic_load(ring.cq_tail_p, &ring.cq_cached_tail, __ATOMIC_ACQUIRE);
        if (ring.cq_cached_head == ring.cq_cached_tail)
          break;
      }

      cqe = &ring.cqes_buf[ring.cq_cached_head & ring.cq_mask];
      cb = (void *) cqe->user_data;
      cqe_res = cqe->res;
      flags = cqe->flags;
      ++ring.cq_cached_head;
      /* RELEASE completion back to the kernel */
      __atomic_store(ring.cq_head_p, &ring.cq_cached_head, __ATOMIC_RELEASE);

      if (cb != NULL) {
        io_callback_pop(&ring.pending_ios, cb);
        io_callback_dispatch(&ring, cb, cqe_res, &flags);
      }
    }

    cb = ring.retry_ios;
    ring.retry_ios = NULL;
    while (cb != NULL) {
      struct io_callback *current_cb = cb;
      io_callback_pop(&cb, current_cb);

      ret = io_callback_dispatch(&ring, current_cb, -EAGAIN, NULL);
      if (ret == -EAGAIN)
        break;
    }
    ring.retry_ios = io_callback_concat(cb, ring.retry_ios);
  }

  destroy_io_uring(&ring);
  return ret;
}

int main() {
  int ret;

  ret = run_server();
  return ret < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
