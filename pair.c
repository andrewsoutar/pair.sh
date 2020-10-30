#include <stdbool.h>

#include <errno.h>

#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>

#include <sys/types.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include "config.h"

enum {
  POLLFD_NET_SOCK,              /* Must be the last one */
  N_POLLFDS
};

struct event_loop {
  struct pollfd *pollfds;
  bool terminated;
};

struct net_status {
  enum { NET_PROTO_CONNECTING, NET_PROTO_START, NET_PROTO_TERM } state;
  size_t n_sockets, n_alloc, addr_i;
};

static void net_handle(struct event_loop *e, struct net_status *net_status) {
  int fd, ret;

  fd = e->pollfds[POLLFD_NET_SOCK].fd;
  if (fd < 0) {
    if (e->terminated)
      return;
    net_status->state = NET_PROTO_CONNECTING;
    net_status->n_sockets = 0;
    net_status->n_alloc = 1;
    net_status->addr_i = 0;
  }

  if (e->terminated) {
    for (size_t i = 0; i < net_status->n_sockets; ++i) {
      if (e->pollfds[POLLFD_NET_SOCK + i].fd >= 0) {
        close(e->pollfds[POLLFD_NET_SOCK + i].fd);
        e->pollfds[POLLFD_NET_SOCK + i] = -1;
      }
    }
    return;
  }

  switch (net_status->state) {
  case NET_PROTO_CONNECTING: {
    bool force_new_conn = false;
    size_t fill_i;

    for (size_t i = 0; i < net_status->n_sockets; ++i) {
      fd = e->pollfds[POLLFD_NET_SOCK + i].fd;
      if (fd >= 0 && e->pollfds[POLLFD_NET_SOCK + i].revents) {
        struct sockaddr_storage dummy;
        e->pollfds[POLLFD_NET_SOCK + i].fd = -1;
        ret = getpeername(fd, (struct sockaddr *) &dummy, sizeof dummy);
        if (!ret)
          goto connected;
        if (i == net_status->n_sockets - 1 &&
            net_status->addr_i >= sizeof config_addrs / sizeof *config_addrs) {
          /* We're at the end, so let's figure out the error message */
          ret = -errno;
          if (ret == -ENOTCONN) {
            /* read() will return the socket's error */
            read(p->fd, &(char[1]) { 0 }, 1);
            ret = -errno;
          }
        }
        force_new_conn = true;
        close(fd);
      }
    }

    fd = -1;
    if (force_new_conn || net_status->n_sockets == 0 || fixme timed out) {
      while (net_status->addr_i < sizeof config_addrs / sizeof *config_addrs) {
        struct sockaddr_storage ss;

        ret = parse_config_addr(&config_addrs[net_status->addr_i++], &ss);
        if (ret)
          continue;

        ret = tcp_socket_init(ss.ss_family);
        if (ret < 0)
          continue;
        fd = ret;

        do {
          ret = connect(fd, (struct sockaddr *) &ss, sizeof ss);
          if (ret)
            ret = -errno;
        } while (ret == -EINTR || ret == -EAGAIN);
        if (!ret)
          goto connected;
        if (ret == -EINPROGRESS)
          break;
        close(fd);
        fd = -1;
      }
    }

    fill_i = 0;
    for (size_t i = 0; i < net_status->n_sockets; ++i)
      if (e->pollfds[POLLFD_NET_SOCK + i].fd >= 0)
        e->pollfds[POLLFD_NET_SOCK + (fill_i++)] =
          e->pollfds[POLLFD_NET_SOCK + i];
    net_status->n_sockets = fill_i;

    if (fd >= 0) {
      struct pollfd *pollfd;
      if (net_status->n_alloc < net_status->n_sockets + 1) {
        size_t new_size;
        struct pollfd *new_pollfds;

        new_size = net_status->n_alloc * 2;
        new_pollfds =
          realloc(e->pollfds,
                  sizeof *e->pollfds * (POLLFD_NET_SOCK + new_size));
        if (new_pollfds == NULL) {
          close(fd);
          if (net_status->n_sockets) {
            /* Retry this address after another socket has closed */
            --net_status->addr_i;
            return;
          } else {
            ret = -ENOMEM;
            goto connect_err;
          }
        }
        e->pollfds = new_pollfds;
        net_status->n_alloc = new_size;
      }
      pollfd = &e->pollfds[POLLFD_NET_SOCK + (net_status->n_sockets++)];
      pollfd->fd = fd;
      pollfd->events = POLLOUT;
    }

    if (!net_status->n_sockets) {
    connect_err:
      log_error(-ret, "establishing connection");
      e->terminated = true;
    }
    return;

  connected:
    for (size_t i = 0; i < net_status->n_sockets; ++i)
      if ((*pollfds)[POLLFD_NET_SOCK + i].fd >= 0)
        close((*pollfds)[POLLFD_NET_SOCK + i].fd);
    net_status->connected = true;
    net_status->state = NET_PROTO_START;
    net_status->n_sockets = 1;
    (*pollfds)[POLLFD_NET_SOCK].fd = fd;
    (*pollfds)[POLLFD_NET_SOCK].events = 0;
    if (net_status->n_alloc > 1) {
      struct pollfd *new_pollfds;

      new_pollfds = realloc(e->pollfds, sizeof *e->pollfds * N_POLLFDS);
      if (new_pollfds != NULL) {
        e->pollfds = new_pollfds;
        net_status->n_alloc = 1;
      }
    }
  }

    /* FIXME we might be able to remove this case and handle with fallthrough */
  case NET_PROTO_START:

    fixme;

  }
}

static int run() {
  struct event_loop e = { 0 };
  struct net_status net_status;
  int ret;

  e.pollfds = malloc(sizeof *pollfds * N_POLLFDS);
  if (e.pollfds == NULL)
    return -ENOMEM;
  for (size_t i = 0; i < N_POLLFDS; ++i)
    e.pollfds[i] = (struct pollfd) { .fd = -1 };

  while (1) {
    net_handle(&e, &net_status);

    ret = poll(e.pollfds, N_POLLFDS + net_status.n_sockets - 1, fixme timeout);
    if (ret < 0 && ret != -EAGAIN && ret != -EINTR)
      return ret;
  }
}
