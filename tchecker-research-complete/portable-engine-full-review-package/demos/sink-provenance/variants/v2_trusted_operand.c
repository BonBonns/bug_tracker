/* v2 — PATCH: only the sink operand changes, user -> safe. */
void write_out(int fd, char *buf, int n);
int strlen_(char *s);

void emit(int fd, char *user, char *safe) {
	write_out(fd, safe, strlen_(safe));
}
