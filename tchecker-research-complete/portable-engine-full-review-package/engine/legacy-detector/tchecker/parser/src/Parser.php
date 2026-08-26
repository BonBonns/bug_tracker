<?php declare( strict_types = 1);

// report on errors, except notices
error_reporting( E_ALL & ~E_NOTICE);

/**
 * This program looks for PHP files in a given directory and dumps ASTs.
 *
 * @author Malte Skoruppa <skoruppa@cs.uni-saarland.de>
 *
 * Local modifications (parser review fixes):
 *   F1 - AST version is no longer silently hardcoded. It is pinned to 50 (the version the
 *        downstream Java interpreter is built against) but validated at startup: if the installed
 *        ext-ast does not support it we ABORT loudly instead of crashing per-file or, worse,
 *        silently producing a structure the interpreter mis-reads (versions >=70 add AST_PROP_GROUP
 *        and extra NULL children, which makes the detector report ZERO findings). The version can be
 *        overridden via PHPJOERN_AST_VERSION for experiments, with a warning.
 *   F2 - dropped (unparseable) files are recorded and reported, so coverage gaps are visible. NOTE:
 *        php-ast parses a whole file atomically and exposes no partial AST, so genuine partial
 *        recovery is not possible without replacing the parser; visibility is the practical fix.
 *   F3 - each file is read exactly once (file_get_contents + ast\parse_code), and the toplevel line
 *        count is derived from that same buffer instead of re-reading via count(file($path)).
 *   F4 - a provenance manifest (php / ext-ast / AST version, files parsed & dropped) is emitted for
 *        reproducibility.
 */

require_once 'Exporter.php';
require_once 'CSVExporter.php';
require_once 'GraphMLExporter.php';

$path = null; // file/folder to be parsed
$format = Exporter::JEXP_FORMAT; // format to use for export (default: jexp)
$nodefile = CSVExporter::NODE_FILE; // name of node file when using CSV format (default: nodes.csv)
$relfile = CSVExporter::REL_FILE; // name of relationship file when using CSV format (default: rels.csv)
$outfile = GraphMLExporter::GRAPHML_FILE; // name of output file when using GraphML format (default: graph.xml)
$scriptname = null; // this script's name
$startcount = 0; // the start count for numbering nodes

// --- parser review additions ---------------------------------------------------------------------
// AST format version. The downstream Java interpreter (PHPCSVNodeInterpreter / PHPCSVEdgeInterpreter)
// is built against version 50. Newer versions restructure declarations and SILENTLY yield zero
// findings, so 50 is pinned by default. Override only for experiments via PHPJOERN_AST_VERSION.
$ast_version = (int)(getenv('PHPJOERN_AST_VERSION') ?: 50);
$parsed_count = 0;        // number of files successfully parsed
$dropped_files = [];      // [ ['path'=>..., 'error'=>...], ... ] for files that could not be parsed
// -------------------------------------------------------------------------------------------------

/**
 * Parses the cli arguments.
 *
 * @return Boolean that indicates whether the given arguments are
 *         fine.
 */
function parse_arguments() {

  global $argv;
  
  if( !isset( $argv)) {
    if( false === (boolean) ini_get( 'register_argc_argv')) {
      error_log( '[ERROR] Please enable register_argc_argv in your php.ini.');
    }
    else {
      error_log( '[ERROR] No $argv array available.');
    }
    echo PHP_EOL;
    return false;
  }

  // Remove the script name (first argument)
  global $scriptname;
  $scriptname = array_shift( $argv);

  if( count( $argv) === 0) {
    error_log( '[ERROR] Missing argument.');
    return false;
  }

  // Set the path and remove from command line (last argument)
  global $path;
  $path = (string) array_pop( $argv);

  // Parse options
  $longopts  = ["help", "version", "format:", "nodes:", "relationships:", "out:", "count:"];
  $options = getopt( "hvf:n:r:o:c:", $longopts);
  if( $options === FALSE) {
    error_log( '[ERROR] Could not parse command line arguments.');
    return false;
  }

  // Help?
  if( isset( $options['help']) || isset( $options['h'])) {
    print_version();
    echo PHP_EOL;
    print_usage();
    echo PHP_EOL;
    print_help();
    exit( 0);
  }

  // Version?
  if( isset( $options['version']) || isset( $options['v'])) {
    print_version();
    exit( 0);
  }

  // Format?
  if( isset( $options['format']) || isset( $options['f'])) {
    global $format;
    switch( $options['format'] ?? $options['f']) {
    case "jexp":
      $format = Exporter::JEXP_FORMAT;
      break;
    case "neo4j":
      $format = Exporter::NEO4J_FORMAT;
      break;
    case "graphml":
      $format = Exporter::GRAPHML_FORMAT;
      break;
    default:
      error_log( "[WARNING] Unknown format '{$options['f']}', using jexp format.");
      $format = Exporter::JEXP_FORMAT;
      break;
    }
  }

  // Nodes file? (for CSV output)
  if( isset( $options['nodes']) || isset( $options['n'])) {
    global $nodefile;
    $nodefile = $options['nodes'] ?? $options['n'];
  }

  // Relationships file? (for CSV output)
  if( isset( $options['relationships']) || isset( $options['r'])) {
    global $relfile;
    $relfile = $options['relationships'] ?? $options['r'];
  }

  // Output file? (for XML output)
  if( isset( $options['out']) || isset( $options['o'])) {
    global $outfile;
    $outfile = $options['out'] ?? $options['o'];
  }

  // Start count?
  if( isset( $options['count']) || isset( $options['c'])) {
    global $startcount;
    $startcount = (int)($options['count'] ?? $options['c']);
  }

  return true;
}

/**
 * Prints a version message.
 */
function print_version() {

  $version = 'UNKNOWN';

  // Note: Only works on Unix :-p
  if( file_exists( ".git/HEAD"))
    if( preg_match( '/^ref: (.+)$/', file_get_contents( ".git/HEAD"), $matches))
      if( file_exists( ".git/{$matches[1]}"))
        $version = substr( file_get_contents( ".git/{$matches[1]}"), 0, 7);

  echo "PHPJoern parser utility, commit {$version}", PHP_EOL;
}

/**
 * Prints a usage message.
 */
function print_usage() {

  global $scriptname;
  echo 'Usage: php '.$scriptname.' [options] <file|folder>', PHP_EOL;
}

/**
 * Prints a help message.
 */
function print_help() {

  echo 'Options:', PHP_EOL;
  echo '  -h, --help                 Display help message', PHP_EOL;
  echo '  -v, --version              Display version information', PHP_EOL;
  echo '  -f, --format <format>      Format to use for the output files: "jexp" (default), "neo4j", or "graphml"', PHP_EOL;
  echo '  -n, --nodes <file>         Output file for nodes (for CSV output, i.e., neo4j or jexp modes)', PHP_EOL;
  echo '  -r, --relationships <file> Output file for relationships (for CSV output, i.e., jexp or neo4j modes)', PHP_EOL;
  echo '  -o, --out <file>           Output file for entire graph (for XML output, i.e., graphml mode)', PHP_EOL;
  echo '  -c, --count <number>       Initial value of node counter (defaults to 0)', PHP_EOL;
  echo 'Environment:', PHP_EOL;
  echo '  PHPJOERN_AST_VERSION       Override the AST format version (default 50; other values are', PHP_EOL;
  echo '                             unsupported by the downstream detector and only for experiments)', PHP_EOL;
}

/**
 * Parses and generates an AST for a single file.
 *
 * @param $path     Path to the file
 * @param $exporter An Exporter instance to use for exporting
 *                  the AST of the parsed file.
 *
 * @return The node index of the exported file node, or -1 if there
 *         was an error.
 */
function parse_file( $path, $exporter) : int {

  global $ast_version, $parsed_count, $dropped_files;

  $finfo = new SplFileInfo( $path);
  echo "Parsing file ", $finfo->getPathname(), PHP_EOL;

  try {
    // F3: read the file exactly once and reuse the buffer for both parsing and the line count
    // (the old code parsed via ast\parse_file and then re-read the whole file via count(file($path))).
    $code = file_get_contents( $path);
    if( $code === false)
      throw new ParseError( "could not read file");

    $ast = ast\parse_code( $code, $ast_version);

    // line count of the toplevel node, derived from the already-read buffer; matches count(file())
    $endline = substr_count( $code, "\n");
    if( strlen( $code) > 0 && substr( $code, -1) !== "\n")
      $endline++;

    // The above may throw a ParseError. We only export to the output
    // file(s) if that didn't happen.
    $fnode = $exporter->store_filenode( $finfo->getFilename());
    $tnode = $exporter->store_toplevelnode( Exporter::TOPLEVEL_FILE, $path, 1, $endline);
    $astroot = $exporter->export( $ast, $tnode);
    $exporter->store_rel( $tnode, $astroot, "PARENT_OF");
    $exporter->store_rel( $fnode, $tnode, "FILE_OF");
    $parsed_count++;
    //echo ast_dump( $ast), PHP_EOL;
  }
  catch( ParseError $e) {
    // F2: php-ast parses a file atomically; on a syntax error there is no partial AST to recover,
    // so the whole file is necessarily dropped. We record it (path + reason) so the resulting
    // coverage gap is visible in the provenance manifest rather than silent.
    $fnode = -1;
    $dropped_files[] = ['path' => $path, 'error' => $e->getMessage()];
    error_log( "[ERROR] In $path: ".$e->getMessage());
  }

  return $fnode;
}

/**
 * Parses and generates ASTs for all PHP files buried within a
 * directory.
 *
 * @param $path     Path to the directory
 * @param $exporter An Exporter instance to use for exporting
 *                  the ASTs of all parsed files.
 * @param $top      Boolean indicating whether this call
 *                  corresponds to the top-level call of the
 *                  function. We wouldn't need this if I didn't
 *                  insist on the root directory of a project
 *                  getting node index 0. But, I do insist.
 *
 * @return If the directory corresponding to the function call finds
 *         itself interesting, it stores a directory node for itself
 *         and this function returns the index of that
 *         node. Otherwise, returns -1. A directory finds itself
 *         interesting if it contains PHP files, or if one of its
 *         child directories finds itself interesting. -- As a special
 *         case, the root directory of a project (corresponding to the
 *         top-level call) always finds itself interesting and always
 *         stores a directory node for itself.
 */
function parse_dir( $path, $exporter, $top = true) : int {

  // save any interesting directory/file indices in the current folder
  $found = [];
  // if the current folder finds itself interesting, we will create a
  // directory node for it and return its index
  $dirnode = $top ? $exporter->store_dirnode( basename( $path)) : -1;

  $dhandle = opendir( $path);

  // iterate over everything in the current folder
  while( false !== ($filename = readdir( $dhandle))) {
    $finfo = new SplFileInfo( build_path( $path, $filename));

    if( $finfo->isFile() && $finfo->isReadable() && in_array( strtolower( $finfo->getExtension()), ['php','inc','phar']))
      $found[] = parse_file( $finfo->getPathname(), $exporter);
    else if( $finfo->isDir() && $finfo->isReadable() && $filename !== '.' && $filename !== '..')
      if( -1 !== ($childdir = parse_dir( $finfo->getPathname(), $exporter, false)))
        $found[] = $childdir;
  }

  // if the current folder finds itself interesting...
  if( !empty( $found)) {
    if( !$top)
      $dirnode = $exporter->store_dirnode( basename( $path));
    foreach( $found as $i => $nodeindex)
      $exporter->store_rel( $dirnode, $nodeindex, "DIRECTORY_OF");
  }

  closedir( $dhandle);

  return $dirnode;
}

/**
 * Builds a file path with the appropriate directory separator.
 *
 * @param ...$segments Unlimited number of path segments.
 *
 * @return The file path built from the path segments.
 */
function build_path( ...$segments) {

  return join( DIRECTORY_SEPARATOR, $segments);
}

/**
 * F4: write a provenance manifest and print a one-line summary so runs are reproducible and any
 * dropped-file coverage gaps are visible.
 */
function emit_provenance() {
  global $ast_version, $parsed_count, $dropped_files;
  $manifest = [
    'php_version'        => PHP_VERSION,
    'ext_ast_version'    => phpversion( 'ast'),
    'ast_format_version' => $ast_version,
    'parsed_files'       => $parsed_count,
    'dropped_files'      => count( $dropped_files),
    'dropped'            => $dropped_files,
    'timestamp'          => date( 'c'),
  ];
  @file_put_contents( 'parse_manifest.json', json_encode( $manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
  fwrite( STDERR, "[provenance] php=".PHP_VERSION." ext-ast=".phpversion('ast').
          " ast_version={$ast_version} parsed={$parsed_count} dropped=".count( $dropped_files).
          ( empty( $dropped_files) ? "" : " (see parse_manifest.json for the ".count( $dropped_files)." unparseable file(s))").
          PHP_EOL);
}

/*
 * Main script
 */
if( parse_arguments() === false) {
  print_usage();
  echo PHP_EOL;
  print_help();
  exit( 1);
}

// F1: validate the required AST version up front. Fail loudly rather than silently degrade.
$supported = function_exists( 'ast\\get_supported_versions') ? ast\get_supported_versions( false) : [];
if( !in_array( $ast_version, $supported, true)) {
  error_log( "[FATAL] AST format version {$ast_version} is not supported by ext-ast ".phpversion('ast').
             " (supported: ".( empty($supported) ? "unknown" : implode( ',', $supported)).
             "). The detector's interpreter is built for version 50; install/pin an ext-ast that ".
             "still provides it (e.g. php-ast<=1.1.x), or set PHPJOERN_AST_VERSION to a supported ".
             "value AT YOUR OWN RISK. Aborting to avoid silently producing an unreadable AST.");
  exit( 2);
}
if( $ast_version !== 50) {
  error_log( "[WARNING] Using AST format version {$ast_version} (PHPJOERN_AST_VERSION override). The ".
             "downstream detector was validated ONLY on version 50; versions >=70 restructure ".
             "declarations (AST_PROP_GROUP, extra NULL children) and cause silent under-reporting.");
}

// Check that source exists and is readable
if( !file_exists( $path) || !is_readable( $path)) {
  error_log( '[ERROR] The given path does not exist or cannot be read.');
  exit( 1);
}

$exporter = null;
// Determine whether source is a file or a directory
if( is_file( $path)) {
  try {
    if( $format === Exporter::GRAPHML_FORMAT)
      $exporter = new GraphMLExporter( $outfile, $startcount);
    else // either NEO4J_FORMAT or JEXP_FORMAT
      $exporter = new CSVExporter( $format, $nodefile, $relfile, $startcount);
  }
  catch( IOError $e) {
    error_log( "[ERROR] ".$e->getMessage());
    exit( 1);
  }
  parse_file( $path, $exporter);
}
elseif( is_dir( $path)) {
  try {
    if( $format === Exporter::GRAPHML_FORMAT)
      $exporter = new GraphMLExporter( $outfile, $startcount);
    else // either NEO4J_FORMAT or JEXP_FORMAT
      $exporter = new CSVExporter( $format, $nodefile, $relfile, $startcount);
  }
  catch( IOError $e) {
    error_log( "[ERROR] ".$e->getMessage());
    exit( 1);
  }
  parse_dir( $path, $exporter);
}
else {
  error_log( '[ERROR] The given path is neither a regular file nor a directory.');
  exit( 1);
}

emit_provenance();

echo "Done.", PHP_EOL;
