#ifndef PAIR_SH__CONFIG_H__
#define PAIR_SH__CONFIG_H__

#include <netinet/in.h>

static const struct config_addr {
  sa_family_t af;
  const char *addr;
} config_addrs[] = {
  { AF_INET6, "2001:19f0:5:5631:5400:2ff:fec1:8565" },
  { AF_INET,  "45.76.15.36" }
};

static const in_port_t config_port = 278;

#endif  /* #ifndef PAIR_SH__CONFIG_H__ */
