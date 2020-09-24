#include <stdio.h>

int main(int argc, char *argv[argc]) {
  for (size_t i = 0; i < argc; ++i) {
    puts(argv[i]);
  }
  printf("Hello, world!\n");
}
