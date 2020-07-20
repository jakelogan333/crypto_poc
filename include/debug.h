#ifndef DEBUG_H
#define DEBUG_H

#define DBG_PRINT(fmt, ...) \
            do { if (DEBUG) wprintf(fmt, __VA_ARGS__); } while (0)

#endif