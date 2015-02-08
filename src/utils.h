#include <stdbool.h>

bool vtls_c_strcaseequal(char *, char *);
char vtls_ascii_toupper(char);

#define vtls_safefree(ptr) do {  \
    free(ptr);                  \
    ptr = NULL;                 \
} while(0);
