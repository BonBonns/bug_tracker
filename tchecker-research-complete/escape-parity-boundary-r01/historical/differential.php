<?php
// Parser-correctness differential ONLY. Two published quote-boundary rules are applied
// to synthetic quoted-text inputs; nothing else from either version is executed.
// FAULTY   (published <= 7.109): one-character negative lookbehind
// CORRECTED(published    7.110): escape-run parity via alternation of non-escape runs
//                                and backslash-pairs
$FAULTY    = "/'(.*?)(?<!\\\\)'/S";
$CORRECTED = "/'((?:[^'\\\\]++|\\\\.)*+)'/sS";

echo "faulty regex   (actual): " . $FAULTY . "\n";
echo "corrected regex(actual): " . $CORRECTED . "\n\n";

// Even-length escape run (2 backslashes) directly before a quote.
// Parity rule: even run => the quote TERMINATES the string.
$even = <<<'EOT'
'abc\\', 'next'
EOT;

// Odd-length escape run (1 backslash) directly before a quote.
// Parity rule: odd run => the quote is ESCAPED, string continues.
$odd = <<<'EOT'
'abc\', 'next'
EOT;

function run($label, $pattern, $subject) {
    $n = preg_match_all($pattern, $subject, $m, PREG_SET_ORDER);
    echo sprintf("  %-10s matches=%d", $label, $n);
    for ($i = 0; $i < $n; $i++) {
        echo sprintf(" | [%d] content=%s", $i, var_export($m[$i][1], true));
    }
    echo "\n";
    return array($n, $m);
}

echo "=== INPUT A: even-length escape run (2) before the quote ===\n";
echo "  raw subject: " . $even . "\n";
list($fn, $fm) = run("faulty",    $FAULTY,    $even);
list($cn, $cm) = run("corrected", $CORRECTED, $even);
echo "  DIFFER: " . (($fn !== $cn || $fm !== $cm) ? "YES" : "no") . "\n\n";

echo "=== INPUT B: odd-length escape run (1) before the quote ===\n";
echo "  raw subject: " . $odd . "\n";
list($fn2, $fm2) = run("faulty",    $FAULTY,    $odd);
list($cn2, $cm2) = run("corrected", $CORRECTED, $odd);
echo "  DIFFER: " . (($fn2 !== $cn2 || $fm2 !== $cm2) ? "YES" : "no") . "\n";
