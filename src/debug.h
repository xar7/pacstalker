#ifndef DEBUG_H
#define DEBUG_H

#ifdef DEBUG
#define DBG(...) fprintf(stderr, __VA_ARGS__)
#else
#define DBG(...)
#endif /* DEBUG */

#endif /* DEBUG_H */
