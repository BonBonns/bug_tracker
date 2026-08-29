#include <string.h>
/* POS1: local array, concrete offset -> recognize, base=buf cap100 off10 remaining90 */
void pos1(char *src, int n){ char buf[100]; memcpy(&buf[10], src, n); }
/* POS2: local array, symbolic offset -> recognize, offset unresolved */
void pos2(char *src, int n, int k){ char buf[50]; memcpy(&(buf[k]), src, 60); }
/* POS3: local array, oversized concrete at offset -> remaining vs length */
void pos3(char *src){ char buf[20]; memcpy(&buf[5], src, 40); }
/* NEG1: read of arr[i] -> not a write, must NOT recognize */
int neg1(void){ char buf[100]; return buf[10]; }
/* NEG2: bare local dest -> v2's existing domain, cap1 must NOT double-handle */
void neg2(char *src, int n){ char buf[100]; memcpy(buf, src, n); }
/* NEG3: address-of non-indexed local -> not &(base[index]) */
void neg3(char *src, int n){ char buf[100]; memcpy(&buf, src, n); }
