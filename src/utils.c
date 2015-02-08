#include "utils.h"

/* This function will return the respective uppercase character for ASCII
 * characters only. All other characters are returned as-is */
char vtls_ascii_toupper(char x)
{
  switch(x) {
    case 'a': return 'A';
    case 'b': return 'B';
    case 'c': return 'C';
    case 'd': return 'D';
    case 'e': return 'E';
    case 'f': return 'F';
    case 'g': return 'G';
    case 'h': return 'H';
    case 'i': return 'I';
    case 'j': return 'J';
    case 'k': return 'K';
    case 'l': return 'L';
    case 'm': return 'M';
    case 'n': return 'N';
    case 'o': return 'O';
    case 'p': return 'P';
    case 'q': return 'Q';
    case 'r': return 'R';
    case 's': return 'S';
    case 't': return 'T';
    case 'u': return 'U';
    case 'v': return 'V';
    case 'w': return 'W';
    case 'x': return 'X';
    case 'y': return 'Y';
    case 'z': return 'Z';
    default: return x;
    }
}

bool vtls_c_strcaseequal(char *p1, char *p2)
{
  if(p1 == p2)
    return true;

  while(*p1 && *p2) {
    if(vtls_ascii_toupper(*p1) != vtls_ascii_toupper(*p2))
      break;

    *p1++;
    *p2++;
  }
  return(vtls_ascii_toupper(*p1) == vtls_ascii_toupper(*p2));
}
