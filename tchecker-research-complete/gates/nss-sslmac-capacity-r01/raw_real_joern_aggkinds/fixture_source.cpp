// AGGKINDS-PROBE-2: exercises the actual destcapacity pipeline (memcpy is a
// registered operand-role callee) for struct/union/class members, bare and
// offset-shaped, both through the named type and through a typedef alias of
// that same type -- to test whether the aggregate-kind classification (and
// therefore the union fail-closed check) survives an alias existing in the
// same translation unit.
extern "C" void *memcpy(void *dest, const void *src, unsigned long n);

struct NamedStruct {
    unsigned char buffer[256];
};

union NamedUnion {
    unsigned char buffer[256];
    unsigned int asInt;
};

class NamedClass {
public:
    unsigned char buffer[256];
};

typedef struct NamedStruct StructAlias;
typedef union NamedUnion UnionAlias;

void copyStructBare(NamedStruct *obj, unsigned char *src, unsigned long n) {
    memcpy(obj->buffer, src, n);
}

void copyStructOffset(NamedStruct *obj, unsigned char *src, unsigned long n, unsigned long off) {
    memcpy(obj->buffer + off, src, n);
}

void copyStructIndexOffset(NamedStruct *obj, unsigned char *src, unsigned long n, unsigned long off) {
    memcpy(&obj->buffer[off], src, n);
}

void copyUnionBare(NamedUnion *u, unsigned char *src, unsigned long n) {
    memcpy(u->buffer, src, n);
}

void copyUnionOffset(NamedUnion *u, unsigned char *src, unsigned long n, unsigned long off) {
    memcpy(&u->buffer[off], src, n);
}

void copyClassBare(NamedClass *c, unsigned char *src, unsigned long n) {
    memcpy(c->buffer, src, n);
}

void copyViaStructAlias(StructAlias *sa, unsigned char *src, unsigned long n) {
    memcpy(sa->buffer, src, n);
}

void copyViaUnionAlias(UnionAlias *ua, unsigned char *src, unsigned long n) {
    memcpy(ua->buffer, src, n);
}
