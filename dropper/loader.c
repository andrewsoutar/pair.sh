/* gcc -o loader.bin -Wl,--oformat=binary loader.c -ffreestanding -nostdlib -lgcc -O3 -static -static-pie -fno-asynchronous-unwind-tables -Wl,-M | grep _start */

#include <limits.h>
#include <stdalign.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdnoreturn.h>

#include <linux/auxvec.h>
#include <linux/elf.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/mman.h>
#include <linux/random.h>
#include <linux/types.h>
#include <linux/unistd.h>

typedef __kernel_ssize_t ssize_t;

/* On Linux x64, off_t is a long */
typedef long off_t;
#define OFF_MAX LONG_MAX
#define OFF_MIN LONG_MIN


/* With -nostdlib, we are required to have an implementation of memcmp, memset, memcpy, and memmove */
int memcmp(const void *s1_, const void *s2_, size_t n_) {
  register const void *s1 asm("rsi") = s1_;
  register const void *s2 asm("rdi") = s2_;
  register const size_t n asm("rcx") = n_;
  signed char ret;
  asm("repz cmpsb; setab %[ret]; sbbb $0, %[ret]"
      : [ret] "=r" (ret)
      : "r" (s1), "r" (s2), "r" (n) : "cc");
  return (signed int) ret;
}
#define memcmp __builtin_memcmp

void *memset(void *s_, int c_, size_t n_) {
  register const void *s asm("rdi") = s_;
  register unsigned char c asm("al") = (unsigned char) c_;
  register size_t n asm("rcx") = n_;
  asm volatile("rep stosb" : "+r" (s), "+r" (n) : "r" (c) : "memory");
  return s_;
}
#define memset __builtin_memset

void *memcpy(void *restrict dest_, const void *restrict src_, size_t n_) {
  register void *dest asm("rdi") = dest_;
  register const void *src asm("rsi") = src_;
  register size_t n asm("rcx") = n_;
  asm volatile("rep movsb" : "+r" (dest), "+r" (src), "+r" (n) :: "memory");
  return dest_;
}
#define memcpy __builtin_memcpy

void *memmove(void *dest_, const void *src_, size_t n_) {
  register void *dest asm("rdi") = dest_;
  register const void *src asm("rsi") = src_;
  register size_t n asm("rcx") = n_;
  if ((uintptr_t) dest_ - (uintptr_t) src_ < n_) {
    dest += n_;
    src += n_;
    asm volatile("std; rep movsb; cld" : "+r" (dest), "+r" (src), "+r" (n) :: "memory");
  } else {
    asm volatile("rep movsb" : "+r" (dest), "+r" (src), "+r" (n) :: "memory");
  }
  return dest_;
}
#define memmove __builtin_memmove

void *memchr(const void *s, int c, size_t n) {
  for (const unsigned char *s_ = (const unsigned char *) s; s_ < (const unsigned char *) s + n; ++s_)
    if (*s_ == (unsigned char) c)
      return (void *) s_;
  return NULL;
}
#define memchr __builtin_memchr

char *strchr(const char *s, int c) {
  do
    if (*s == c)
      return (char *) s;
  while (*(s++) != '\0');
  return NULL;
}

size_t strlen(const char *s) {
  /* We can't use __builtin_strchr here, or GCC will optimize it back into
   * strlen >:[ */
  return strchr(s, '\0') - s;
}

#define strchr __builtin_strchr
#define strlen __builtin_strlen


static uint64_t syscall_nargs(uint64_t number, int nargs, ...) {
  va_list ap;
  uint64_t res = 0;
  register uint64_t arg1 asm("rdi"), arg2 asm("rsi"), arg3 asm("rdx"),
    arg4 asm("r10"), arg5 asm("r8"), arg6 asm("r9");
  va_start(ap, nargs);
  if (nargs >= 1)
    arg1 = va_arg(ap, uint64_t);
  if (nargs >= 2)
    arg2 = va_arg(ap, uint64_t);
  if (nargs >= 3)
    arg3 = va_arg(ap, uint64_t);
  if (nargs >= 4)
    arg4 = va_arg(ap, uint64_t);
  if (nargs >= 5)
    arg5 = va_arg(ap, uint64_t);
  if (nargs >= 6)
    arg6 = va_arg(ap, uint64_t);
  va_end(ap);
  asm volatile("syscall" : "=a" (res) : "a" (number), "r" (arg1), "r" (arg2), "r" (arg3), "r" (arg4), "r" (arg5), "r" (arg6) : "memory", "rcx", "r11");
  return res;
}

#define syscall_helper(nr, arg1, arg2, arg3, arg4, arg5, arg6, nargs, ...) \
  syscall_nargs((nr), (nargs),                                          \
                (uint64_t) (arg1), (uint64_t) (arg2), (uint64_t) (arg3), \
                (uint64_t) (arg4), (uint64_t) (arg5), (uint64_t) (arg6))
#define syscall(nr, ...) syscall_helper((nr), __VA_ARGS__, 6, 5, 4, 3, 2, 1)

noreturn void _Exit(int exit_code) {
  while (1)
    syscall(__NR_exit_group, (uint64_t) exit_code);
}
#define _Exit __builtin__Exit


/* DEBUGGING STUFF */
/* static void debug(const char *msg) { */
/*   syscall(__NR_write, 2, msg, strlen(msg)); */
/* } */
/* static void debug_num(uint64_t num) { */
/*   char buf[16]; */
/*   for (size_t i = 0; i < sizeof buf; ++i) */
/*     buf[i] = "0123456789abcdef"[num >> 4 * (sizeof buf - i - 1) & 0xf]; */
/*   syscall(__NR_write, 2, buf, sizeof buf); */
/* } */


static uint16_t load_le16(const unsigned char *buffer) {
  return (uint16_t) buffer[0] | (uint16_t) buffer[1] << 8;
}
static uint32_t load_le32(const unsigned char *buffer) {
  return (uint32_t) load_le16(buffer) | (uint32_t) load_le16(buffer + 2) << 16;
}
static uint64_t load_le64(const unsigned char *buffer) {
  return (uint64_t) load_le32(buffer) | (uint64_t) load_le32(buffer + 4) << 32;
}


struct buffer {
  int fd;
  unsigned char *data;
  size_t size, fill;
};

static int read_more_bytes(struct buffer *buffer) {
  uint64_t res;
  if (buffer->fill >= buffer->size)
    return -1;
retry:
  res = syscall(__NR_read, buffer->fd, buffer->data + buffer->fill, buffer->size - buffer->fill);
  if (res == -EINTR)
    goto retry;
  if (res > (uint64_t) -4096 || res == 0) {
    buffer->size = 0;           /* This way all future read_more_bytes() will fail */
    return -1;
  }
  buffer->fill += (ssize_t) res;
  return 0;
}

static int ensure_buffer(struct buffer *buffer, size_t n_bytes) {
  while (buffer->fill < n_bytes)
    if (read_more_bytes(buffer) != 0)
      return -1;
  return 0;
}

static size_t buffer_memchr(struct buffer *buffer, int needle, size_t start, size_t end) {
  unsigned char *index;
  while (buffer->fill < end) {
    if ((index = memchr(buffer->data + start, needle, buffer->fill)) != NULL)
      return index - buffer->data;
    start = buffer->fill;
    if (read_more_bytes(buffer) != 0)
      return -1;
  }
  if ((index = memchr(buffer->data + start, needle, end - start)) != NULL)
    return index - buffer->data;
  return -1;
}

static int buffer_memcmp(struct buffer *buffer, size_t start, const void *str, size_t size) {
  if (ensure_buffer(buffer, start + size) != 0) {
    int res = memcmp(buffer->data + start, str, buffer->fill - start);
    return res == 0 ? -1 : res;
  } else {
    return memcmp(buffer->data + start, str, size);
  }
}


static int load_vwi(uint64_t *out, struct buffer *buffer, size_t offset) {
  if (ensure_buffer(buffer, offset + 1) != 0)
    return -1;
  size_t len = buffer->data[offset];
  if (len > 8 || ensure_buffer(buffer, offset + 1 + len) != 0)
    return -1;

  *out = 0;
  for (size_t i = 0; i < len; ++i)
    *out |= 1 << i * 8;
  for (size_t i = 0; i < len; ++i) {
    uint64_t digit = (uint64_t) buffer->data[offset + 1 + i] << i * 8;
    if (offset > UINT64_MAX - digit)
      return -1;
    offset += digit;
  }
  return 0;
}

static int load_base10(uint64_t *out, struct buffer *buffer, size_t offset) {
  *out = 0;
  while (1) {
    if (ensure_buffer(buffer, offset + 1) != 0)
      return -1;
    unsigned char digit = buffer->data[offset++];
    if (digit < 0x30 || digit > 0x39 || *out == 0 && digit == 0x30)
      return 0;
    if (*out > UINT64_MAX / 10)
      return -1;
    *out *= 10;
    if (*out > UINT64_MAX - (digit - 0x30))
      return -1;
    *out += digit - 0x30;
  }
}


static const unsigned char bin_magic[] = {
  0x43, 0x21, 0xCE, 0xCF, 0x48, 0x44, 0x52, 0x40
};
static const unsigned char txt_magic[] = {
  0x43, 0x45, 0x43, 0x46, 0x48, 0x44, 0x52, 0x40
};


struct header {
  uint64_t blob_offset;
  uint64_t blob_size;
};

#define HEADER_SIZE (sizeof bin_magic + 1 + 1 + 2 + 4 + 8 + 8)
#define SEARCH_SIZE 4096
#define SEARCH_BUF_SIZE (SEARCH_SIZE - 1 + HEADER_SIZE)


struct cecf_info {
  uint64_t blob_size;
  bool has_saved_data;
  union { uint64_t blob_offset, saved_data_size; };
  unsigned char saved_data[SEARCH_BUF_SIZE];
};

static int cecf_parse_header(struct cecf_info *info,
                             struct buffer *buffer, size_t offset) {
  if (ensure_buffer(buffer, offset + HEADER_SIZE) != 0)
    return -1;

  size_t parse_idx = offset;

  unsigned char magic[sizeof bin_magic + 1];
  memcpy(magic, buffer->data + parse_idx, sizeof magic);
  if (memcmp(magic, bin_magic, sizeof bin_magic != 0)
      || magic[sizeof bin_magic] != 0x00)
    return -1;
  parse_idx += sizeof magic;

  unsigned char version = buffer->data[parse_idx];
  if (version != 0)
    return -1;
  ++parse_idx;

  size_t header_size = load_le16(buffer->data + parse_idx) * 4;
  if (header_size != HEADER_SIZE)
    return -1;
  parse_idx += 2;

  uint32_t checksum = 0;
  for (size_t i = 0; i < HEADER_SIZE; i += 4)
    checksum += load_le32(buffer->data + offset + i);
  if (checksum != 0)
    return -1;
  parse_idx += 4;

  info->blob_offset = load_le64(buffer->data + parse_idx);
  info->blob_size = load_le64(buffer->data + parse_idx + 8);

  size_t overread = buffer->fill - offset;
  if (info->has_saved_data = info->blob_offset < overread) {
    size_t copy_size = overread - info->blob_offset;
    if (copy_size > info->blob_size)
      copy_size = info->blob_size;
    memcpy(info->saved_data, buffer->data + offset + info->blob_offset, copy_size);
    info->saved_data_size = copy_size;
  } else {
    info->blob_offset -= overread;
  }
  return 0;
}

static int cecf_parse_from_offset(struct cecf_info *info, struct buffer *buffer,
                                  size_t offset_loc, uint64_t offset) {
  if (offset == 0)
    return cecf_parse_header(info, buffer, offset_loc);

    return -1;
  if (offset > OFF_MAX || OFF_MIN + (off_t) offset + (off_t) HEADER_SIZE > 0)
    return -1;
  size_t overread = buffer->fill - offset_loc;
  if (syscall(__NR_lseek, buffer->fd, (off_t) offset - (off_t) overread, SEEK_CUR)
      > (uint64_t) -4096)
    return -1;

  unsigned char header[HEADER_SIZE];
  struct buffer header_buffer = { buffer->fd, header, sizeof header };
  int ret = cecf_parse_header(info, &header_buffer, 0);

  if (ret != 0)
    if (syscall(__NR_lseek, buffer->fd,
                -(off_t) offset + (off_t) overread - (off_t) header_buffer.fill,
                SEEK_CUR)
        > (uint64_t) -4096)
      _Exit(1);                 /* We can't seek back, just bail */
  return ret;
}

static int cecf_parse_from_fd(struct cecf_info *info, int fd) {
  uint64_t res;

  unsigned char data[SEARCH_BUF_SIZE];
  struct buffer buffer = { fd, data, sizeof data };

  size_t search_idx = 0;
keep_searching:
  while (search_idx < SEARCH_SIZE &&
         (search_idx = buffer_memchr(&buffer, bin_magic[0], search_idx, SEARCH_SIZE)) != (size_t) -1) {
    size_t find_loc = search_idx;

    if (buffer_memcmp(&buffer, search_idx, bin_magic, sizeof bin_magic) == 0) {
      uint64_t offset;
      if (load_vwi(&offset, &buffer, search_idx + sizeof bin_magic) == 0)
        if (cecf_parse_from_offset(info, &buffer, find_loc, offset) == 0)
          return 0;
    } else if (buffer_memcmp(&buffer, search_idx, txt_magic, sizeof txt_magic) == 0) {
      uint64_t offset;
      if (load_base10(&offset, &buffer, search_idx + sizeof txt_magic) == 0)
        if (cecf_parse_from_offset(info, &buffer, find_loc, offset) == 0)
          return 0;
    }
    ++search_idx;
  }
  return -1;
}


static void *cecf_load_blob_from_fd(const struct cecf_info *info, int fd) {
  uint64_t res;

  if (info->blob_size > SIZE_MAX)
    return NULL;

  if (!info->has_saved_data && info->blob_offset > 0) {
    if (info->blob_offset > OFF_MAX)
      return NULL;
    off_t offset = info->blob_offset;
    if ((res = syscall(__NR_lseek, fd, offset, SEEK_CUR)) > (uint64_t) -4096) {
      if (res != -ESPIPE)
        return NULL;
    } else {
      offset = 0;
    }

    while (offset > 0) {
      unsigned char buffer[4096];
      size_t size = sizeof buffer;
      if (size > offset)
        size = offset;
      if ((res = syscall(__NR_read, fd, (void *) buffer, size)) > (uint64_t) -4096)
        if (res == -EINTR)
          continue;
        else
          return NULL;
      else if ((ssize_t) res == 0)
        return NULL;
      else
        offset -= (ssize_t) res;
    }
  }

  if ((res = syscall(__NR_mmap, NULL, (size_t) info->blob_size,
                     PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0))
      > (uint64_t) -4096)
    return NULL;
  unsigned char *blob = (void *) res;
  struct buffer blob_buffer = { fd, blob, info->blob_size };
  if (info->has_saved_data) {
    memcpy(blob_buffer.data, info->saved_data, info->saved_data_size);
    blob_buffer.fill = info->saved_data_size;
  }
  if (ensure_buffer(&blob_buffer, info->blob_size) == 0)
    return blob;

  syscall(__NR_munmap, (void *) blob, (size_t) info->blob_size);
  return NULL;
}


struct elf_info {
  void *entry;
  bool exec_stack;
};

static int load_elf(struct elf_info *info, unsigned char *elf, size_t elf_size) {
  uint64_t res;
  info->exec_stack = 1;

  Elf64_Ehdr ehdr;
  if (elf_size < sizeof ehdr)
    return -1;
  memcpy(&ehdr, elf, sizeof ehdr);
  if (ehdr.e_ident[EI_MAG0] != ELFMAG0 ||
      ehdr.e_ident[EI_MAG1] != ELFMAG1 ||
      ehdr.e_ident[EI_MAG2] != ELFMAG2 ||
      ehdr.e_ident[EI_MAG3] != ELFMAG3 ||
      ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
      ehdr.e_ident[EI_DATA] != ELFDATA2LSB ||
      ehdr.e_ident[EI_VERSION] != EV_CURRENT ||
      (ehdr.e_ident[EI_OSABI] != ELFOSABI_NONE &&
       ehdr.e_ident[EI_OSABI] != ELFOSABI_LINUX) ||
      ehdr.e_type != ET_DYN ||
      ehdr.e_machine != EM_X86_64 ||
      ehdr.e_version != EV_CURRENT ||
      ehdr.e_phentsize < sizeof (Elf64_Phdr) ||
      ehdr.e_phnum > elf_size / ehdr.e_phentsize ||
      ehdr.e_phoff > elf_size - ehdr.e_phnum * ehdr.e_phentsize)
    return -1;

  size_t lo = -1, pos = 0, hi = 0;
  for (size_t i = 0; i < ehdr.e_phnum; ++i) {
    Elf64_Phdr phdr;
    memcpy(&phdr, elf + ehdr.e_phoff + i * ehdr.e_phentsize, sizeof phdr);
    if (phdr.p_type == PT_INTERP)
      return -1;
    else if (phdr.p_type == PT_GNU_STACK)
      info->exec_stack = phdr.p_flags & PF_X;
    if (phdr.p_type != PT_LOAD)
      continue;

    if (phdr.p_filesz > phdr.p_memsz ||
        phdr.p_offset > elf_size ||
        phdr.p_filesz > elf_size - phdr.p_offset ||
        phdr.p_memsz > SIZE_MAX ||
        phdr.p_vaddr > SIZE_MAX - phdr.p_memsz ||
        phdr.p_vaddr < pos)
      return -1;

    pos = phdr.p_vaddr;
    if (phdr.p_vaddr < lo)
      lo = phdr.p_vaddr;
    if (pos + phdr.p_memsz > hi)
      hi = pos + phdr.p_memsz;
  }

  lo = lo / 4096 * 4096;
  if (lo >= hi || ehdr.e_entry > hi)
    return -1;

  if ((res = syscall(__NR_mmap, NULL, hi - lo, PROT_EXEC | PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) > (uint64_t) -4096)
    return -1;
  unsigned char *load_base = (void *) res;

  pos = lo;
  for (size_t i = 0; i < ehdr.e_phnum; ++i) {
    Elf64_Phdr phdr;
    memcpy(&phdr, elf + ehdr.e_phoff + i * ehdr.e_phentsize, sizeof phdr);
    if (phdr.p_type != PT_LOAD || phdr.p_memsz == 0)
      continue;

    size_t start_page = phdr.p_vaddr / 4096 * 4096;
    if (pos < start_page) {
      size_t distance = (start_page - pos) / 4096 * 4096;
      if (distance > 0)
        syscall(__NR_munmap, (void *) (load_base + (start_page - distance - lo)),
                distance);
    }
    memcpy(load_base + (phdr.p_vaddr - lo), elf + phdr.p_offset, phdr.p_filesz);
    memset(load_base + (phdr.p_vaddr - lo) + phdr.p_filesz, 0,
           phdr.p_memsz - phdr.p_filesz);
    int new_prot = !(phdr.p_flags & (PF_X | PF_W | PF_R)) ? PROT_NONE :
      (phdr.p_flags & PF_X ? PROT_EXEC : 0) |
      (phdr.p_flags & PF_W ? PROT_WRITE : 0) |
      (phdr.p_flags & PF_R ? PROT_READ : 0);
    syscall(__NR_mprotect, (void *) (load_base + (start_page - lo)),
            (phdr.p_vaddr - start_page) + phdr.p_memsz, new_prot);

    if (phdr.p_vaddr + phdr.p_memsz > pos)
      pos = phdr.p_vaddr + phdr.p_memsz;
  }

  info->entry = load_base + (ehdr.e_entry - lo);
  return 0;
}

static void elf_launch(const struct elf_info *info,
                       const char *const *argv,
                       const char *const *envp,
                       const void *vdso) {
  uint64_t res;
  size_t argv_size = 1, envp_size = 1, auxv_size = 1, extra_size = 0;
  
  for (size_t i = 0; argv[i] != NULL; ++i) {
    /* argv comes from try_${lang}, so argv[1] is the implementation */
    if (i == 1)
      continue;
    ++argv_size;
    extra_size += strlen(argv[i]) + 1;
  }
  for (size_t i = 0; envp[i] != NULL; ++i) {
    ++envp_size;
    extra_size += strlen(envp[i]) + 1;
  }

  if (vdso != NULL)
    ++auxv_size;

  unsigned char random[16];
  if (syscall(__NR_getrandom, (void *) random, sizeof random, GRND_INSECURE)
      == -EINVAL)
    syscall(__NR_getrandom, (void *) random, sizeof random, GRND_NONBLOCK);
  /* Lots of failure cases - ENOSYS, EAGAIN, ...
   * But there's not much else we can do, and I'm not a fan of falling
   * back to RDRAND (or urandom), so let's just pretend that whatever
   * stack junk is already in the buffer is probably fine. */
  ++auxv_size;
  extra_size += sizeof random;

  uintptr_t argc = argv_size - 1;

  size_t vectors_size = sizeof argc
    + sizeof argv_size * sizeof (const char *)
    + envp_size * sizeof (const char *)
    + auxv_size * 2 * sizeof (uintptr_t);
  size_t params_size = (vectors_size + extra_size + 15) / 16 * 16;
  size_t stack_size = (8 * 1024 * 1024 + params_size + 4095) / 4096 * 4096;

  if ((res = syscall(__NR_mmap, NULL, stack_size,
                     (info->exec_stack ? PROT_EXEC : 0) | PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN | MAP_STACK,
                     -1, 0)) > (uint64_t) -4096)
    return;
  unsigned char *stack = (void *) res;
  unsigned char *params = stack + stack_size - params_size;
  unsigned char *params_extra = params + vectors_size;

  unsigned char *params_p = params, *params_extra_p = params_extra;

  const char *nullterm = NULL;
  memcpy(params_p, &argc, sizeof argc);
  params_p += sizeof argc;
  for (size_t i = 0; argv[i] != NULL; ++i) {
    /* See above */
    if (i == 1)
      continue;
    size_t len = strlen(argv[i]) + 1;
    memcpy(params_extra_p, argv[i], len);
    const char *arg = (const char *) params_extra_p;
    memcpy(params_p, &arg, sizeof arg);
    params_p += sizeof arg;
    params_extra_p += len;
  }
  memcpy(params_p, &nullterm, sizeof nullterm);
  params_p += sizeof nullterm;

  for (size_t i = 0; envp[i] != NULL; ++i) {
    size_t len = strlen(envp[i]) + 1;
    memcpy(params_extra_p, envp[i], len);
    const char *env = (const char *) params_extra_p;
    memcpy(params_p, &env, sizeof env);
    params_p += sizeof env;
    params_extra_p += len;
  }
  memcpy(params_p, &nullterm, sizeof nullterm);
  params_p += sizeof nullterm;

  if (vdso != NULL) {
    uintptr_t tag = AT_SYSINFO_EHDR;
    uintptr_t value = (uintptr_t) vdso;
    memcpy(params_p, &tag, sizeof tag);
    params_p += sizeof tag;
    memcpy(params_p, &value, sizeof value);
    params_p += sizeof value;
  }

  {
    memcpy(params_extra_p, random, sizeof random);
    uintptr_t tag = AT_RANDOM;
    uintptr_t value = (uintptr_t) (void *) params_extra_p;
    memcpy(params_p, &tag, sizeof tag);
    params_p += sizeof tag;
    memcpy(params_p, &value, sizeof value);
    params_p += sizeof value;
    params_extra_p += sizeof random;
  }

  {
    uintptr_t tag = AT_NULL;
    uintptr_t value = 0;
    memcpy(params_p, &tag, sizeof tag);
    params_p += sizeof tag;
    memcpy(params_p, &value, sizeof value);
    params_p += sizeof value;
  }

  unsigned char *stack_top = params;
  uintptr_t entry_call = (uintptr_t) info->entry;
  stack_top -= sizeof entry_call;
  memcpy(stack_top, &entry_call, sizeof entry_call);

  asm volatile(
    "movq %[stack_top], %%rsp;"
    "xorl %%eax, %%eax;"
    "xorl %%ecx, %%ecx;"
    "xorl %%edx, %%edx;"
    "xorl %%ebx, %%ebx;"
    "xorl %%esi, %%esi;"
    "xorl %%edi, %%edi;"
    "xorl %%ebp, %%ebp;"
    "xorl %%r8d, %%r8d;"
    "xorl %%r9d, %%r9d;"
    "xorl %%r10d, %%r10d;"
    "xorl %%r11d, %%r11d;"
    "xorl %%r12d, %%r12d;"
    "xorl %%r13d, %%r13d;"
    "xorl %%r14d, %%r14d;"
    "xorl %%r15d, %%r15d;"
    "retq"
    :: [stack_top] "irm" (stack_top));
  __builtin_unreachable();
}


static void try_run_from_fd(int fd, const char *const *argv,
                            const char *const *envp, const void *vdso) {
  struct cecf_info cecf_info;
  if (cecf_parse_from_fd(&cecf_info, fd) != 0)
    return;

  void *elf = cecf_load_blob_from_fd(&cecf_info, fd);

  struct elf_info elf_info;
  if (elf == NULL || load_elf(&elf_info, elf, cecf_info.blob_size) != 0)
    _Exit(1);
  syscall(__NR_munmap, elf, cecf_info.blob_size);

  elf_launch(&elf_info, argv, envp, vdso);
  _Exit(1);
}

int _start(void *argv_, void *envp, void *vdso) {
  uint64_t res;
  char **argv = (char **) argv_;

  int fd = 0;
  if ((res = syscall(__NR_openat, (int) AT_FDCWD, (const char *) argv[0],
                     (int) (O_RDONLY | O_CLOEXEC)))
      <= (uint64_t) -4096) {
    try_run_from_fd((int) res, argv_, envp, vdso);
    syscall(__NR_close, (int) res);
  }

  try_run_from_fd(0, argv_, envp, vdso);

  _Exit(1);
}
