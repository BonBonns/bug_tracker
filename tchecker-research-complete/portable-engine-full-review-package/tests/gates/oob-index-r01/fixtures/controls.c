struct E { long a; long b; };
void safe_loop(void){ int buf[8]; for(int i=0;i<8;i++) buf[i]=0; }        /* i<8==cap -> SAFE */
void safe_const(void){ struct E rg[1]; rg[0].a=1; }                        /* const 0<1 -> SAFE */
void bad_unbounded(int k){ struct E rg[1]; int c=0; for(int i=0;i<k;i++){ rg[c].a=1; c++; } } /* unbounded -> FLAG */
void guarded(int k){ struct E rg[1]; if(k > (int)(sizeof(rg)/sizeof(rg[0]))) return; int c=0; for(int i=0;i<k;i++){ rg[c].a=1; c++; } } /* real guard -> SUPPRESS */
