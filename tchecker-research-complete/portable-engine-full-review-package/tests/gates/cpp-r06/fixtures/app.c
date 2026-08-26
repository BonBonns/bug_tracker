int helper(int x) { return x; }
int passthrough(int a, int b) { return b; }
int constant_value(int x) { return 7; }
int mainflow(int input) { return helper(input); }
void no_value_result(int input) { if (input) return; }
