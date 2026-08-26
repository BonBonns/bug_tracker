package tools.php.ast2cpg;
import java.io.*; import java.util.*;
import ast.php.functionDef.FunctionDef;
import inputModules.csv.csvFuncExtractor.CSVFunctionExtractor;
import cg.*; import cfg.*; import udg.*;
import udg.php.useDefAnalysis.PHPASTDefUseAnalyzer;
import udg.useDefGraph.UseDefGraph;
import ddg.*; import ddg.DefUseCFG.DefUseCFG;

public class ProbeGate18 {
  static Map<Long,Set<Integer>> copyMap(Map<Long,Set<Integer>> src) {
    Map<Long,Set<Integer>> out=new HashMap<Long,Set<Integer>>();
    for(Map.Entry<Long,Set<Integer>> e:src.entrySet()) out.put(e.getKey(),new HashSet<Integer>(e.getValue()));
    return out;
  }
  public static void main(String[] args)throws Exception{
    Main.baseDir=".";
    CSVFunctionExtractor ex=new CSVFunctionExtractor();
    ex.setInterpreters(new PHPCSVNodeInterpreter(),new PHPCSVEdgeInterpreter());
    ex.initialize(new FileReader("nodes.csv"),new FileReader("rels.csv"));
    ASTToCFGConverter a=new ASTToCFGConverter(); a.setFactory(new PHPCFGFactory());
    CFGToUDGConverter b=new CFGToUDGConverter(); b.setASTDefUseAnalyzer(new PHPASTDefUseAnalyzer());
    CFGAndUDGToDefUseCFG c=new CFGAndUDGToDefUseCFG(); DDGCreator d=new DDGCreator();
    HashSet<FunctionDef> roots=new HashSet<FunctionDef>(); FunctionDef r;
    while((r=(FunctionDef)ex.getNextFunction())!=null){roots.add(r); CFG cfg=a.convert(r); UseDefGraph u=b.convert(cfg); DefUseCFG du=c.convert(cfg,u); d.createForDefUseCFG(du);}
    for(FunctionDef root:roots) PHPCGFactory.addFunctionDef(root);
    PHPCGFactory.newInstance();

    Map<Long,Set<Integer>> hardBefore=copyMap(PHPCGFactory.returnTaintPositions);
    Map<Long,Set<Integer>> mayBefore=copyMap(PHPCGFactory.returnMayTaintPositions);
    Map<Long,String> mayResBefore=new HashMap<Long,String>(PHPCGFactory.returnMayTaintResolution);

    ArrayList<FunctionDef> fs=new ArrayList<FunctionDef>(roots); fs.sort(Comparator.comparingLong(FunctionDef::getNodeId));
    for(FunctionDef f:fs){
      ProvenanceEvidenceReporter.Record ev=ProvenanceEvidenceReporter.forFunction(f.getNodeId());
      if(ev.status != ProvenanceEvidenceReporter.Status.NONE || "binaryUnrelated".equals(f.getName()))
        System.out.println("EVID "+f.getName()+" "+ev.render());
    }
    System.out.println("REPORT_MUTATED_HARD="+(!hardBefore.equals(PHPCGFactory.returnTaintPositions)));
    System.out.println("REPORT_MUTATED_MAY="+(!mayBefore.equals(PHPCGFactory.returnMayTaintPositions) || !mayResBefore.equals(PHPCGFactory.returnMayTaintResolution)));
  }
}
