#include <string.h>
/* NEGIDX: negative index -> points before buffer; MUST abstain (not cap+1 remaining) */
void negidx(char *src, int n){ char buf[100]; memcpy(&buf[-1], src, n); }
/* ONEPASTEND: offset == capacity (one-past-the-end); remaining 0; a positive write overflows */
void onepast(char *src){ char buf[10]; memcpy(&buf[10], src, 4); }
/* SYMARITH: symbolic index arithmetic -> offset unresolved, abstain */
void symarith(char *src, int n, int i){ char buf[100]; memcpy(&buf[i + 2], src, n); }
/* SIDEEFFECT: side-effecting index i++ -> abstain (value + pointer validity unresolved) */
void sideeffect(char *src, int n, int i){ char buf[100]; memcpy(&buf[i++], src, n); }
/* UNITMISMATCH: int array, offset elements, literal BYTE width -> unit mismatch, abstain */
void unitmismatch(int *src){ int ibuf[10]; memcpy(&ibuf[3], src, 30); }
