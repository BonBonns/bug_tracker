/* v4 — the LENGTH operand is a literal: positively provable as source-free.
   Contrast operand #1 (abstains) with operand #2 (EXACT, no origin). */
void write_out(int fd, char *buf, int n);

void emit(int fd, char *user, char *safe) {
	static char lit[8];
	write_out(fd, lit, 8);
}
