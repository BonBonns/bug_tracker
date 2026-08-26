package tools.php.ast2cpg;
import java.io.*; import java.util.*;
import ast.php.functionDef.FunctionDef;
import inputModules.csv.csvFuncExtractor.CSVFunctionExtractor;
import cg.*; import cfg.*; import udg.*; import udg.php.useDefAnalysis.PHPASTDefUseAnalyzer;
import udg.useDefGraph.UseDefGraph; import ddg.*; import ddg.DefUseCFG.DefUseCFG;

public class ProbeGate19 {
  static Map<Long,Set<Integer>> copyMap(Map<Long,Set<Integer>> src){
    Map<Long,Set<Integer>> out=new HashMap<>(); for(Map.Entry<Long,Set<Integer>> e:src.entrySet())out.put(e.getKey(),new HashSet<>(e.getValue())); return out;
  }
  static Map<Long,List<Long>> copyMulti(misc.MultiHashMap<Long,Long> src){
    Map<Long,List<Long>> out=new HashMap<>(); for(Long k:src.keySet())out.put(k,new ArrayList<>(src.get(k))); return out;
  }
  public static void main(String[] args)throws Exception{
    Main.baseDir=".";
    CSVFunctionExtractor ex=new CSVFunctionExtractor(); ex.setInterpreters(new PHPCSVNodeInterpreter(),new PHPCSVEdgeInterpreter()); ex.initialize(new FileReader("nodes.csv"),new FileReader("rels.csv"));
    ASTToCFGConverter a=new ASTToCFGConverter(); a.setFactory(new PHPCFGFactory()); CFGToUDGConverter b=new CFGToUDGConverter(); b.setASTDefUseAnalyzer(new PHPASTDefUseAnalyzer()); CFGAndUDGToDefUseCFG c=new CFGAndUDGToDefUseCFG(); DDGCreator d=new DDGCreator();
    HashSet<FunctionDef> roots=new HashSet<>(); FunctionDef r; while((r=(FunctionDef)ex.getNextFunction())!=null){roots.add(r); CFG cfg=a.convert(r); UseDefGraph u=b.convert(cfg); DefUseCFG du=c.convert(cfg,u); d.createForDefUseCFG(du);} for(FunctionDef root:roots)PHPCGFactory.addFunctionDef(root); PHPCGFactory.newInstance();
    Map<Long,Set<Integer>> hardBefore=copyMap(PHPCGFactory.returnTaintPositions); Map<Long,Set<Integer>> mayBefore=copyMap(PHPCGFactory.returnMayTaintPositions); Map<Long,String> mayResBefore=new HashMap<>(PHPCGFactory.returnMayTaintResolution); Map<Long,List<Long>> vulBefore=copyMulti(StaticAnalysis.vulSources);
    Set<String> wanted=new LinkedHashSet<>(Arrays.asList("wrapMay","wrapMay2","wrapMayLocal","wrapMayThroughIdentity","wrapMayConditional","wrapMayConcat","wrapUnknownConcat","identity","concatExactOnly"));
    ArrayList<FunctionDef> fs=new ArrayList<>(roots); fs.sort(Comparator.comparingLong(FunctionDef::getNodeId));
    for(FunctionDef f:fs) if(wanted.contains(f.getName())) { ProvenancePathReporter.Path pth=ProvenancePathReporter.forFunction(f.getNodeId()); System.out.println("PATH_BEGIN "+f.getName()+"\n"+pth.render()+"\nHARD_PROJECTION="+ProvenancePathReporter.hardSourceProjection(pth).isPresent()+"\nPATH_END "+f.getName()); }
    System.out.println("PATH_REPORT_MUTATED_HARD="+(!hardBefore.equals(PHPCGFactory.returnTaintPositions)));
    System.out.println("PATH_REPORT_MUTATED_MAY="+(!mayBefore.equals(PHPCGFactory.returnMayTaintPositions)||!mayResBefore.equals(PHPCGFactory.returnMayTaintResolution)));
    System.out.println("PATH_REPORT_MUTATED_VUL_SOURCES="+(!vulBefore.equals(copyMulti(StaticAnalysis.vulSources))));
  }
}
