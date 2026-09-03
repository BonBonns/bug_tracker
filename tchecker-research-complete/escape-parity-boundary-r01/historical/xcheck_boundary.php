<?php
// Structural-verdict <-> engine-behaviour cross-check.
// Each pattern is applied to two synthetic subjects: one whose closing quote follows an
// EVEN-length escape run (the quote terminates the value) and one whose quote follows an
// ODD-length run (the quote is escaped, the value continues). Parser behaviour only.
$cases = json_decode(file_get_contents($argv[1]), true);
foreach ($cases as $c) {
    $q = $c['q']; $body = $c['p'];
    // EVEN: value is  abc\\  then a real closing quote, then a second value
    $even = $q . 'abc\\\\' . $q . ', ' . $q . 'next' . $q;
    // ODD: the quote after abc\ is escaped, so the value runs on to the next quote
    $odd  = $q . 'abc\\' . $q . ', ' . $q . 'next' . $q;
    $row = array('id' => $c['id']);
    foreach (array('even' => $even, 'odd' => $odd) as $k => $subject) {
        $n = @preg_match_all('/' . $body . '/s', $subject, $m, PREG_SET_ORDER);
        if ($n === false) { $row[$k] = 'ENGINE_ERROR'; continue; }
        $vals = array();
        for ($i = 0; $i < $n; $i++) $vals[] = isset($m[$i][1]) ? $m[$i][1] : $m[$i][0];
        $row[$k] = $vals;
    }
    // correct EVEN handling: recovers the two intended values
    $row['even_ok'] = ($row['even'] === array('abc\\\\', 'next'));
    // correct ODD handling: the escaped quote does NOT end the value
    $row['odd_ok'] = (is_array($row['odd']) && count($row['odd']) >= 1
                      && $row['odd'][0] === 'abc\\' . $q . ', ');
    echo json_encode($row) . "\n";
}
