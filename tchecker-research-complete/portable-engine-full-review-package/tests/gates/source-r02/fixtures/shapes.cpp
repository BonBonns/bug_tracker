// SOURCE-R02b characterization: aggregate external-write -> field propagation.
struct Inner { int q; };
struct Img { int w; int h; Inner in; };
void sink(int n);
size_t fread(void *p, size_t a, size_t b, void *f);
void *fp; int safe();

void h1_whole_to_field()    { Img img; fread(&img,12,1,fp); sink(img.w); }              // should inherit
void h2_whole_to_nested()   { Img img; fread(&img,12,1,fp); sink(img.in.q); }           // nested inherit
void h3_field_same()        { Img img; fread(&img.w,4,1,fp); sink(img.w); }             // same field inherit
void h4_field_sibling()     { Img img; img.h = safe(); fread(&img.w,4,1,fp); sink(img.h); } // sibling must NOT
void h5_ext_then_overwrite(){ Img img; fread(&img,12,1,fp); img.w = safe(); sink(img.w); }  // overwrite kills
void h6_overwrite_then_ext(){ Img img; img.w = safe(); fread(&img,12,1,fp); sink(img.w); }  // ext wins
void h7_may_alias(int c)    { Img a; Img b; Img *p = c ? &a : &b; fread(p,12,1,fp); sink(a.w); } // MAY only
// k-controls (consolidated from the separate fixture): overwrite variants.
void k1_cond_overwrite(int c) { Img img; fread(&img,12,1,fp); if (c) img.w = safe(); sink(img.w); }
void k3_nested_overwrite()    { Img img; fread(&img,12,1,fp); img.in.q = safe(); sink(img.in.q); }
void k4_nested_sibling()      { Img img; fread(&img,12,1,fp); img.in.q = safe(); sink(img.w); }
// k5: a GENUINE MAY-targeted overwrite (the earlier version never wrote through p
// and was therefore vacuous). FILE_INPUT must stay POSSIBLE: killed if p==&a,
// surviving if p==&b.
void k5_may_overwrite(int c)  { Img a; Img b; fread(&a,12,1,fp); Img *p = c ? &a : &b; p->w = safe(); sink(a.w); }
void h8_ptr_aggregate(Img *p){ fread(p,12,1,fp); sink(p->w); }                          // through pointer
void h9_array()             { int buf[4]; fread(buf,16,1,fp); sink(buf[0]); }           // array element
