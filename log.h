#define _GNU_SOURCE

#include <stdio.h>
#include <stdarg.h>

#include <errno.h>
#include <string.h>

#ifndef PAIR_SH__LOG_H__
#define PAIR_SH__LOG_H__

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

#endif
