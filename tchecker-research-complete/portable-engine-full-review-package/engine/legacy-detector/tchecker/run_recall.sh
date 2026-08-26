#!/usr/bin/env bash
# run_recall.sh — recall stress suite for the TChecker engine.
# Each test is a minimal repro where $_GET (source) flows toward echo (XSS sink).
# label FIRE   = taint SHOULD reach the sink -> a "Vul:" is expected; no Vul = RECALL GAP.
# label NOFIRE = taint is genuinely blocked (sanitizer/control) -> no Vul expected.
#
#   ./run_recall.sh [/path/to/engine/tchecker]
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ENG="${1:-$HERE/engine/tchecker}"
ENG="$(cd "$ENG" && pwd)"   # absolutize: the run loop cd's into temp dirs, so relative paths would break
CP="$ENG/out:$ENG/lib/commons-csv-1.8.jar:$ENG/lib/commons-cli-1.4.jar:$ENG/lib/json-20190722.jar:$ENG/lib/commons-lang3-3.10.jar"
export PHP7="${PHP7:-$(command -v php)}"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# ---- define tests: name | dimension | label | writes PHP into $d ----
emit() { # $1 dir
  local d="$1"
  case "$(basename "$d")" in
  cb_cuf_fn)      cat > "$d/a.php" <<'P'
<?php function snk($a){ echo $a; } call_user_func('snk', $_GET['x']);
P
  ;;
  cb_cuf_method)  cat > "$d/a.php" <<'P'
<?php class H { function run($a){ echo $a; } } $h=new H(); call_user_func(array($h,'run'), $_GET['x']);
P
  ;;
  cb_cufa)        cat > "$d/a.php" <<'P'
<?php function snk($a){ echo $a; } call_user_func_array('snk', array($_GET['x']));
P
  ;;
  cb_varfn)       cat > "$d/a.php" <<'P'
<?php function snk($a){ echo $a; } $cb='snk'; $cb($_GET['x']);
P
  ;;
  cb_hook_method) cat > "$d/a.php" <<'P'
<?php class H { function run(){ echo $_GET['x']; } } $h=new H(); add_action('init', array($h,'run'));
P
  ;;
  obj_factory)    cat > "$d/a.php" <<'P'
<?php class R { public $v; function render(){ echo $this->v; } }
function make($t){ $r=new R(); $r->v=$t; return $r; } $x=make($_GET['x']); $x->render();
P
  ;;
  obj_nested_prop) cat > "$d/a.php" <<'P'
<?php class Helper { public $v; function render(){ echo $this->v; } }
class Main { public $helper; function __construct($t){ $this->helper=new Helper(); $this->helper->v=$t; } function go(){ $this->helper->render(); } }
$m=new Main($_GET['x']); $m->go();
P
  ;;
  obj_return_new) cat > "$d/a.php" <<'P'
<?php class X { public $v; function __construct($t){ $this->v=$t; } function render(){ echo $this->v; } }
function mk($t){ return new X($t); } $o=mk($_GET['x']); $o->render();
P
  ;;
  obj_array_disp) cat > "$d/a.php" <<'P'
<?php class R { public $v; function render(){ echo $this->v; } }
$objs=array(); $r=new R(); $r->v=$_GET['x']; $objs[0]=$r; $objs[0]->render();
P
  ;;
  ret_id)         cat > "$d/a.php" <<'P'
<?php function id($x){ return $x; } echo id($_GET['x']);
P
  ;;
  ret_sanitized)  cat > "$d/a.php" <<'P'
<?php function s($x){ return esc_html($x); } echo s($_GET['x']);
P
  ;;
  ret_field)      cat > "$d/a.php" <<'P'
<?php class O { public $f; } function gf($o){ return $o->f; } $o=new O(); $o->f=$_GET['x']; echo gf($o);
P
  ;;
  ret_nested)     cat > "$d/a.php" <<'P'
<?php function wrap($x){ return $x; } function h($x){ return wrap($x); } echo h($_GET['x']);
P
  ;;
  arr_copy)       cat > "$d/a.php" <<'P'
<?php $a=array(); $a['x']=$_GET['p']; $b=$a; echo $b['x'];
P
  ;;
  arr_dynkey)     cat > "$d/a.php" <<'P'
<?php $a=array(); $k='x'; $a[$k]=$_GET['p']; $u='x'; echo $a[$u];
P
  ;;
  inc_crossfile)  cat > "$d/main.php" <<'P'
<?php $t=$_GET['x']; include __DIR__.'/sink.php';
P
                  cat > "$d/sink.php" <<'P'
<?php echo $t;
P
  ;;
  sani_inline)    cat > "$d/a.php" <<'P'
<?php echo esc_html($_GET['x']);
P
  ;;
  sani_seeded)    cat > "$d/a.php" <<'P'
<?php function f($a){ echo esc_html($a); } f($_GET['x']);
P
  ;;
  af_ctx_arg)     cat > "$d/a.php" <<'P'
<?php function f($x){ return apply_filters('tag', esc_html($x), $x); } echo f($_GET['x']);
P
  ;;
  ip_direct_fwd)  cat > "$d/a.php" <<'P'
<?php function f($x){ return $x; } echo f($_GET['x']);
P
  ;;
  ip_one_relevant) cat > "$d/a.php" <<'P'
<?php function f($safe, $unused){ return $safe; } echo f(esc_html($_GET['x']), $_GET['raw_context']);
P
  ;;
  ip_second_arg)  cat > "$d/a.php" <<'P'
<?php function f($a, $b){ return $b; } echo f('safe', $_GET['x']);
P
  ;;
  ip_multi_contrib) cat > "$d/a.php" <<'P'
<?php function f($a, $b){ return $a . $b; } echo f($_GET['x'], 'safe');
P
  ;;
  ip_unresolved)  cat > "$d/a.php" <<'P'
<?php echo unknown_helper($_GET['x']);
P
  ;;
  ip_nested_fwd)  cat > "$d/a.php" <<'P'
<?php function b($x){ return $x; } function a($x){ return b($x); } echo a($_GET['x']);
P
  ;;
  esac
}

TESTS="
cb_cuf_fn|callback|FIRE
cb_cuf_method|callback|FIRE
cb_cufa|callback|FIRE
cb_varfn|callback|FIRE
cb_hook_method|callback|FIRE
obj_factory|obj-dispatch|FIRE
obj_nested_prop|obj-dispatch|FIRE
obj_return_new|obj-dispatch|FIRE
obj_array_disp|obj-dispatch|FIRE
ret_id|return-summary|FIRE
ret_sanitized|return-summary|NOFIRE
ret_field|return-summary|FIRE
ret_nested|return-summary|FIRE
arr_copy|array|FIRE
arr_dynkey|array|FIRE
inc_crossfile|include|FIRE
sani_inline|sanitizer|NOFIRE
sani_seeded|sanitizer|NOFIRE
af_ctx_arg|apply_filters-arg-scoping|NOFIRE
ip_direct_fwd|interproc-return-summary|FIRE
ip_one_relevant|interproc-return-summary|NOFIRE
ip_second_arg|interproc-return-summary|FIRE
ip_multi_contrib|interproc-return-summary|FIRE
ip_unresolved|interproc-return-summary|FIRE
ip_nested_fwd|interproc-return-summary|FIRE
"

printf "%-16s %-14s %-8s %-8s %s\n" TEST DIMENSION EXPECT GOT RESULT
printf -- "-%.0s" {1..62}; echo
pass=0; gap=0; ctrl=0; total_fire=0
for line in $TESTS; do
  name="${line%%|*}"; rest="${line#*|}"; dim="${rest%%|*}"; label="${rest##*|}"
  d="$WORK/$name"; mkdir -p "$d"; emit "$d"
  ( cd "$d" && "$ENG/parser/php2ast" . >/dev/null 2>&1 )
  vul=$( cd "$d" && env WP_XSS_ONLY=1 WP_SEED_MODE=all java -cp "$CP" tools.php.ast2cpg.Main . 2>/dev/null | grep -c "Vul: " )
  got=$([ "$vul" -gt 0 ] && echo FIRE || echo NOFIRE)
  if [ "$label" = FIRE ]; then
    total_fire=$((total_fire+1))
    if [ "$got" = FIRE ]; then res="ok";      pass=$((pass+1)); else res="** RECALL GAP **"; gap=$((gap+1)); fi
  else
    if [ "$got" = NOFIRE ]; then res="ok(ctrl)"; ctrl=$((ctrl+1)); else res="!! control fired (over-taint)"; fi
  fi
  printf "%-16s %-14s %-8s %-8s %s\n" "$name" "$dim" "$label" "$got" "$res"
done
printf -- "-%.0s" {1..62}; echo
echo "recall on 'should-fire' constructs: $pass/$total_fire modeled   ($gap gaps)"
echo "sanitizer controls held: $ctrl"
