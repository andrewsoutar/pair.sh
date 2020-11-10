#ifndef CONFIG_H
#define CONFIG_H config.h
#endif

#define QUOTE(x) QUOTE_HELPER(x)
#define QUOTE_HELPER(x) #x
#include QUOTE(CONFIG_H)
#undef QUOTE_HELPER
#undef QUOTE
