/* v3 — operand comes from an EXTERNAL function whose body is unavailable.
   The engine must abstain rather than assert "no parameter origin". */
void write_out(int fd, char *buf, int n);
int strlen_(char *s);
char *make_buf(void);

void emit(int fd, char *user, char *safe) {
	char *g = make_buf();
	write_out(fd, g, strlen_(g));
}
