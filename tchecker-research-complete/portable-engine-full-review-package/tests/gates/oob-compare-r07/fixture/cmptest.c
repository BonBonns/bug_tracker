#include <string.h>
#include <stdlib.h>
/* Two-sided comparison extent: safety needs n <= cap(A) AND n <= cap(B).
   A bound for A must NOT certify B. */

int safe_both(void){ char a[32]; char b[32]; return memcmp(a, b, 32); }        /* SAFE: 32<=32, 32<=32 */
int safe_min(void){  char a[32]; char b[8];  return memcmp(a, b, 8);  }        /* SAFE: 8<=32, 8<=8   */
int unsafe_on_b(void){ char a[32]; char b[8];  return memcmp(a, b, 32); }      /* UNSAFE on B: 32>8   */
int unsafe_sizeof_a(void){ char a[32]; char b[8]; return memcmp(a, b, sizeof(a)); } /* UNSAFE: sizeof(A)=32 > cap(B)=8 */
int safe_strncmp(void){ char a[16]; char b[16]; return strncmp(a, b, 16); }    /* SAFE */
int unsafe_strncmp_b(void){ char a[64]; char b[4]; return strncmp(a, b, 64); } /* UNSAFE on B: 64>4 */
int variable_n(int n){ char a[32]; char b[16]; return memcmp(a, b, n); }       /* extent variable -> abstain */
int ptr_operand(char* p){ char b[8]; return memcmp(p, b, 8); }                 /* A is pointer, no cap -> A abstains; B ok */
int main(void){ return 0; }
