<?php
// PCRE engine harness. Applies each PCRE pattern to each subject and reports the values
// it recovers. Parser behaviour only; nothing else from any package is executed.
$cases = json_decode(file_get_contents($argv[1]), true);
foreach ($cases as $c) {
    if ($c['dialect'] !== 'PCRE') continue;
    $n = @preg_match_all('/' . $c['pattern'] . '/s', $c['subject'], $m, PREG_SET_ORDER);
    $row = array('rule_id'=>$c['rule_id'],'dialect'=>'PCRE','engine'=>'php-pcre',
                 'run_length'=>$c['run_length'],'parity'=>$c['parity']);
    if ($n === false) { $row['engine_error'] = true; echo json_encode($row)."\n"; continue; }
    $vals = array();
    for ($i=0;$i<$n;$i++) $vals[] = isset($m[$i][1]) ? $m[$i][1] : $m[$i][0];
    $row['recovered'] = $vals;
    $row['matches_parity_rule'] = ($vals === $c['expected']);
    echo json_encode($row)."\n";
}
