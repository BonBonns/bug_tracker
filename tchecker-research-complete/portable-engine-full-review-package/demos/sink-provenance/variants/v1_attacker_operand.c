/* v1 — the security-relevant operand is the ATTACKER-CONTROLLED parameter. */
void write_out(int fd, char *buf, int n);
int strlen_(char *s);

void emit(int fd, char *user, char *safe) {
	write_out(fd, user, strlen_(user));
}
