// SINK-R01 gate: the SAME provenance question at a call-argument observation
// point. Ground truth per argument is in the assertions.
int ext();
void sink(int a, int b);

void s1(int x)            { sink(x, 0); }                                  // arg0 EXACT[0]; arg1 no origin
void s2(int x, int c)     { int t = x; if (c) t = ext(); sink(0, t); }     // arg1 POSSIBLE_UNBOUNDED may={0}
void s3(int x, int y, int c) { int t = c ? x : y; sink(t, 0); }            // arg0 AMBIGUOUS may={0,1}
void s4(int x, int i)     { int buf[4]; buf[i] = x; sink(buf[0], 0); }     // arg0 UNRESOLVED
void s5(int x)            { sink(7, 0); }                                  // arg0 no origin (constant)
