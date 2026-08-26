// SOURCE-R02 gate: FILE_INPUT origin, plus negative controls.
struct Img { int w; int h; };
void alloc_sink(int n);
int ext();
size_t fread(void *p, size_t a, size_t b, void *f);
void *fp;

void g1_file_to_sink()      { Img img; fread(&img, 8, 1, fp); alloc_sink(img.w); }   // FILE_INPUT reaches sink
void g2_no_source(int p)    { int t = 5; alloc_sink(t); }                            // NEG: constant, no origin
void g3_param_unchanged(int p) { alloc_sink(p); }                                    // NEG: parameter origin preserved
void g4_unrelated_local()   { Img img; fread(&img, 8, 1, fp); int t = 9; alloc_sink(t); } // NEG: sink not from source
