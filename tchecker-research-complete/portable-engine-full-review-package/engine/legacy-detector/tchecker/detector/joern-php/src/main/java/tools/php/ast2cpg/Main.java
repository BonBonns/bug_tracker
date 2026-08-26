package tools.php.ast2cpg;

import java.io.FileReader;
import java.io.IOException;
import java.util.HashSet;

import org.apache.commons.cli.ParseException;

import ast.php.functionDef.FunctionDef;
import cfg.ASTToCFGConverter;
import cfg.CFG;
import cfg.PHPCFGFactory;
import cg.CG;
import cg.PHPCGFactory;
import cg.PruneCG;
import ddg.CFGAndUDGToDefUseCFG;
import ddg.DDGCreator;
import ddg.DataDependenceGraph.DDG;
import ddg.DefUseCFG.DefUseCFG;
import inputModules.csv.KeyedCSV.exceptions.InvalidCSVFile;
import inputModules.csv.csvFuncExtractor.CSVFunctionExtractor;
import outputModules.common.Writer;
import outputModules.common.WriterCG;
import outputModules.csv.MultiPairCSVWriterImpl;
import outputModules.csv.exporters.CSVCFGExporter;
import outputModules.csv.exporters.CSVCGExporter;
import outputModules.csv.exporters.CSVDDGExporter;
import udg.CFGToUDGConverter;
import udg.php.useDefAnalysis.PHPASTDefUseAnalyzer;
import udg.useDefGraph.UseDefGraph;

public class Main {

	// command line interface
	static CommandLineInterface cmdLine = new CommandLineInterface();

	// converters
	static CSVFunctionExtractor extractor = new CSVFunctionExtractor();
	//static PHPCFGFactory cfgFactory = new PHPCFGFactory();
	static ASTToCFGConverter ast2cfgConverter = new ASTToCFGConverter();
	static CFGToUDGConverter cfgToUDG = new CFGToUDGConverter();
	static CFGAndUDGToDefUseCFG udgAndCfgToDefUseCFG = new CFGAndUDGToDefUseCFG();
	static DDGCreator ddgCreator = new DDGCreator();

	// exporters
	static CSVCFGExporter csvCFGExporter = new CSVCFGExporter();
	static CSVDDGExporter csvDDGExporter = new CSVDDGExporter();
	static CSVCGExporter csvCGExporter = new CSVCGExporter();
	
	//basedir
	public static String baseDir;

	public static void main(String[] args) throws InvalidCSVFile, IOException {
		String phase = "INIT";
		try {
			// parse command line
			phase = "PARSE_COMMAND_LINE";
			parseCommandLine(args);

			// initialize readers
			//String nodeFilename = cmdLine.getNodeFile();
			//String edgeFilename = cmdLine.getEdgeFile();
			baseDir = cmdLine.getBaseDir();
			String nodeFilename = "nodes.csv";
			String edgeFilename = "rels.csv";

			phase = "READ_CSV";
			FileReader nodeFileReader = new FileReader(nodeFilename);
			FileReader edgeFileReader = new FileReader(edgeFilename);

			// initialize converters

			extractor.setInterpreters(new PHPCSVNodeInterpreter(), new PHPCSVEdgeInterpreter());

			extractor.initialize(nodeFileReader, edgeFileReader);
			ast2cfgConverter.setFactory(new PHPCFGFactory());
			cfgToUDG.setASTDefUseAnalyzer(new PHPASTDefUseAnalyzer());

			// initialize writers
			MultiPairCSVWriterImpl csvWriter = new MultiPairCSVWriterImpl();
			MultiPairCSVWriterImpl cgcsvWriter = new MultiPairCSVWriterImpl();
			csvWriter.openEdgeFile( ".", "cpg_edges.csv");
			cgcsvWriter.openEdgeFile(".", "call_graph.csv");
			Writer.setWriterImpl(csvWriter);
			WriterCG.setWriterImpl(cgcsvWriter);

			// let's go...
			phase = "CFG_UDG_DDG_CONSTRUCTION";
			FunctionDef rootnode;
			HashSet<FunctionDef> rootSet = new HashSet<FunctionDef>();
			while ((rootnode = (FunctionDef)extractor.getNextFunction()) != null) {
				rootSet.add(rootnode);

				CFG cfg = ast2cfgConverter.convert(rootnode);
				csvCFGExporter.writeCFGEdges(cfg);

				UseDefGraph udg = cfgToUDG.convert(cfg);
				DefUseCFG defUseCFG = udgAndCfgToDefUseCFG.convert(cfg, udg);
				DDG ddg = ddgCreator.createForDefUseCFG(defUseCFG);
				csvDDGExporter.writeDDGEdges(ddg);
			}
			phase = "CALL_GRAPH_CONSTRUCTION";
			for(FunctionDef root: rootSet) {
				PHPCGFactory.addFunctionDef( root);
			}
			// now that we wrapped up all functions, let's finish off with the call graph
			CG cg = PHPCGFactory.newInstance();
			csvCGExporter.writeCGEdges(cg);

			//Prune call graph
			//PruneCG();
			//PruneCG.handle();

			phase = "STATIC_ANALYSIS_DETECTION";
			StaticAnalysis detecter = new StaticAnalysis();

			phase = "CLOSE_WRITERS";
			csvWriter.closeEdgeFile();
			cgcsvWriter.closeEdgeFile();

			// ITEM18 coverage reporting: a consolidated, human-facing summary printed right next to
			// the completion marker, so "0 findings" is never seen without its coverage caveats in
			// the same breath. entries_considered/entries_unclassified are properties of the shared
			// entry-point model, not per-shape, so a representative (first non-zero) value is used
			// rather than summed; sinks_considered/paths_found/paths_emitted genuinely differ per
			// shape and ARE summed; truncation states/entries are unioned (not summed) to avoid
			// double-counting the same truncated frontier appearing under multiple shapes.
			System.out.println("=== SCAN COVERAGE SUMMARY ===");
			System.out.println("Total candidate findings (Vul:): " + StaticAnalysis.totalVulCount);
			java.util.List<PHPCGFactory.PassResult> ctrlResults = PHPCGFactory.allCtrlReachResults;
			boolean anyCtrlReachRun = false;
			for( PHPCGFactory.PassResult r : ctrlResults ) if( r.sinksConsidered > 0 ) { anyCtrlReachRun = true; break; }
			if( anyCtrlReachRun ) {
				int entriesConsidered = 0, entriesUnclassified = 0, entriesDropped = 0;
				boolean inconsistentEntries = false;
				java.util.Set<String> truncStatesUnion = new java.util.HashSet<String>();
				java.util.Set<Long> truncEntriesUnion = new java.util.HashSet<Long>();
				java.util.Map<String,Integer> truncByReasonUnion = new java.util.LinkedHashMap<String,Integer>();
				int totalSinksConsidered = 0, totalPathsFound = 0, totalPathsEmitted = 0;
				for( PHPCGFactory.PassResult r : ctrlResults ) {
					if( r.sinksConsidered == 0 ) continue;   // NO_SINKS_OF_THIS_SHAPE_REGISTERED -- skip
					if( entriesConsidered == 0 ) entriesConsidered = r.entriesConsidered;
					else if( entriesConsidered != r.entriesConsidered ) inconsistentEntries = true;
					entriesUnclassified = Math.max(entriesUnclassified, r.entriesUnclassifiedTraversed);
					entriesDropped = Math.max(entriesDropped, r.entriesDroppedNotReachable);
					truncStatesUnion.addAll(r.truncStates);
					truncEntriesUnion.addAll(r.truncEntries);
					for( java.util.Map.Entry<String,Integer> e : r.truncByReason.entrySet() ) {
						Integer cur = truncByReasonUnion.get(e.getKey());
						truncByReasonUnion.put(e.getKey(), cur == null ? e.getValue() : Math.max(cur, e.getValue()));
					}
					totalSinksConsidered += r.sinksConsidered;
					totalPathsFound += r.pathsFound;
					totalPathsEmitted += r.pathsEmitted;
				}
				System.out.println("Reachability coverage (CTRLREACH):");
				System.out.println("  modeled entry points: " + entriesConsidered + " considered, "
					+ entriesUnclassified + " with UNKNOWN access classification"
					+ (inconsistentEntries ? " (NOTE: entries_considered varied across shapes -- see stderr ACCOUNTING lines per-shape)" : ""));
				System.out.println("  entries dropped as unreachable: " + entriesDropped);
				System.out.println("  sink categories considered (summed across shapes): " + totalSinksConsidered
					+ ", entry->sink paths found: " + totalPathsFound + ", paths emitted: " + totalPathsEmitted);
				System.out.println("  traversal truncation: " + truncEntriesUnion.size() + " entries affected, "
					+ truncStatesUnion.size() + " unique truncated states, by reason=" + truncByReasonUnion);
				if( !PHPCGFactory.unknownReasonBuckets.isEmpty() ) {
					System.out.println("  entry-access UNKNOWN reason breakdown (ranked by count):");
					java.util.List<java.util.Map.Entry<String,java.util.Set<Long>>> bucketList =
						new java.util.ArrayList<java.util.Map.Entry<String,java.util.Set<Long>>>(PHPCGFactory.unknownReasonBuckets.entrySet());
					bucketList.sort((a, b) -> b.getValue().size() - a.getValue().size());
					for( java.util.Map.Entry<String,java.util.Set<Long>> be : bucketList ) {
						System.out.println("    " + be.getValue().size() + "  " + be.getKey());
					}
					if( System.getenv("WP_UNKNOWN_SAMPLE") != null ) {
						// Sample from the ACTUAL "executable" (still-unknown) bucket specifically --
						// NOT the raw reasonTopLevelFileScope set, which contains every file-scope
						// entry regardless of whether it was later excluded as declaration-only. The
						// earlier version of this sample used the raw set, which meant declaration-
						// only entries (correctly excluded from the UNKNOWN count) could still appear
						// in the "sample" with no indication they weren't actually contributing to it
						// -- a real, confirmed misleading-diagnostic bug, not an engine correctness
						// bug (isFileScopeDeclarationOnly itself was verified correct via direct trace).
						java.util.Set<Long> executableOnly = PHPCGFactory.unknownReasonBuckets.get("top_level_file_scope_executable");
						System.out.println("  top_level_file_scope_executable SAMPLE (up to 200, file paths, ACTUAL unresolved bucket only):");
						int shown = 0;
						if( executableOnly != null ) for( Long id : executableOnly ) {
							if( shown++ >= 200 ) break;
							System.out.println("    node=" + id + " file=" + PHPCGFactory.getDir(id));
						}
					}
				}
			} else {
				System.out.println("Reachability coverage (CTRLREACH): not run (WP_SINKS=extended/priv_esc/file_read/"
					+ "file_delete/post_write/user_meta not enabled for this scan)");
			}
			System.out.println("Dynamic dispatch / reflection / closures: NOT exhaustively covered. Resolved at "
				+ "least " + PHPCGFactory.dynDispatchSitesResolved + " dispatch site(s) ("
				+ PHPCGFactory.dynDispatchEdgesAdded + " call-graph edge(s)) via known patterns (literal callable, "
				+ "array(obj,'method'), 'Class::method' string, add_action/add_filter registry, indirect "
				+ "getter-registry dispatch). This is a FLOOR, not a percentage -- no total count of dynamic-"
				+ "dispatch call sites (resolved or not) is currently tracked. An unresolved site stays "
				+ "conservative rather than being silently treated as safe, but may under-connect the call graph.");
			System.out.println("PROP_IDENTITY calls=" + tools.php.ast2cpg.StaticAnalysis.PI_calls
				+ " indexed_hits=" + tools.php.ast2cpg.StaticAnalysis.PI_indexedHits
				+ " fallback_scans=" + tools.php.ast2cpg.StaticAnalysis.PI_fallbackScans
				+ " unresolved=" + tools.php.ast2cpg.StaticAnalysis.PI_unresolved
				+ " (fallback_scans is a WP_VERIFY_PROP_INDEX=1-only mismatch count between the "
				+ "indexed lookup and the pre-ITEM49 raw-scan oracle -- see ITEM49; 0 when unset)");
			System.out.println("GET_CLASS_ID calls=" + PHPCGFactory.GCID_calls
				+ " cumulative_ms=" + (PHPCGFactory.GCID_cumulativeNanos / 1_000_000)
				+ " (ITEM52: classDef.keySet() linear scan replaced with direct HashMap.get())");
			System.out.println("FIND_SINGLE_INCLUDE calls=" + PHPCGFactory.FSIM_calls
				+ " fallback_scans=" + PHPCGFactory.FSIM_fallbackScans
				+ " (ITEM53: reuses ITEM43's includeOrEvalByFunc index; fallback_scans is a "
				+ "WP_VERIFY_INCLUDE_INDEX=1-only mismatch count, 0 when unset)");
			System.out.println("CTYPE_GUARD calls=" + PHPCGFactory.CTYPE_calls
				+ " fallback_scans=" + PHPCGFactory.CTYPE_fallbackScans
				+ " (ITEM55: new IfStatement-by-funcId index; fallback_scans is a "
				+ "WP_VERIFY_CTYPE_INDEX=1-only mismatch count, 0 when unset)");
			if( !PHPCGFactory.scanSiteStats.isEmpty() ) {
				System.out.println("=== SCAN SITE PERFORMANCE INVENTORY (ITEM52) ===");
				java.util.List<java.util.Map.Entry<String,long[]>> entries =
					new java.util.ArrayList<java.util.Map.Entry<String,long[]>>(PHPCGFactory.scanSiteStats.entrySet());
				entries.sort((a, b) -> Long.compare(b.getValue()[1], a.getValue()[1]));
				for( java.util.Map.Entry<String,long[]> e : entries ) {
					System.out.println("SCANSITE_" + e.getKey() + " calls=" + e.getValue()[0]
						+ " total_nodes=" + e.getValue()[1]);
				}
				System.out.println("=== END SCAN SITE PERFORMANCE INVENTORY ===");
			}
			System.out.println("=== END SCAN COVERAGE SUMMARY ===");

			// Explicit, affirmative completion signal. Confirmed via a real crash this session
			// (Smush 4.2.0: a ClassCastException inside STATIC_ANALYSIS_DETECTION aborted the
			// process after the CFG/call-graph phases had already produced real output, silently
			// producing "0 Vul:" lines with no other visible signal short of checking the exit
			// code and stderr) that "some output exists" must never be read as "analysis
			// completed" -- this marker is the only thing that should be trusted for that.
			System.out.println("ANALYSIS_STATUS=COMPLETE");
		} catch (Throwable t) {
			// Deliberately catches Throwable, not just checked exceptions -- a crash anywhere in
			// the pipeline (parsing, CFG/DDG construction, call-graph construction, or detection)
			// must be reported, not silently swallowed by falling through to whatever partial
			// output already exists. Prints to BOTH stdout (so it's visible in the same stream as
			// Vul:/EVJSON output a consumer might be scanning) and stderr (with the full stack
			// trace, for diagnosis), then exits non-zero so the failure can't be missed by a
			// caller that only checks "did anything print".
			System.out.println("ANALYSIS_STATUS=FAILED phase=" + phase
				+ " exception=" + t.getClass().getName()
				+ " message=" + t.getMessage());
			System.err.println("ANALYSIS_STATUS=FAILED phase=" + phase
				+ " exception=" + t.getClass().getName());
			t.printStackTrace();
			System.exit(1);
		}
	}

	private static void parseCommandLine(String[] args)	{

		try {
			cmdLine.parseCommandLine(args);
		}
		catch (RuntimeException | ParseException e) {
			printHelpAndTerminate(e);
		}
	}

	private static void printHelpAndTerminate(Exception e) {

		System.err.println(e.getMessage());
		cmdLine.printHelp();
		System.exit(0);
	}

}


