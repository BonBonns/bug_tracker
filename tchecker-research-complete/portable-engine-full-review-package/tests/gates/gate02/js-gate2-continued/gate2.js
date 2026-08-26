function sink_f(y) { return y; }
function middle_f(x) { return sink_f(x); }
function main(input) { return middle_f(input); }
