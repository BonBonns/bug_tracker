package cg;

import java.util.*;
import ast.ASTNode;
import ast.expressions.*;
import ast.php.functionDef.*;
import ast.functionDef.ParameterList;
import ast.statements.jump.ReturnStatement;
import inputModules.csv.csv2ast.ASTUnderConstruction;

/**
 * Gate 19: read-only path-level provenance evidence.
 *
 * This reporter never mutates returnTaintPositions, returnMayTaintPositions,
 * frontendCallResolution, call2mtd, or StaticAnalysis.vulSources.  A path is
 * eligible for hard-source serialization only when every contributing segment
 * is EXACT and the underlying function summary is hard/proven.
 */
public final class ProvenancePathReporter {
  private ProvenancePathReporter() {}

  public static final class Step {
    public final String kind;
    public final long nodeId;
    public final String detail;
    public final String resolution;
    Step(String kind,long nodeId,String detail,String resolution){
      this.kind=kind; this.nodeId=nodeId; this.detail=detail; this.resolution=resolution;
    }
    public String render(){ return kind+" node="+nodeId+" resolution="+resolution+" detail=["+detail+"]"; }
  }

  public static final class Path {
    public final long functionId;
    public final String functionName;
    public final String status;
    public final String pathResolution;
    public final List<Integer> parameterPositions;
    public final List<Step> steps;
    public final boolean hardSourceEligible;
    Path(long fid,String name,String status,String res,List<Integer> pos,List<Step> steps,boolean hard){
      this.functionId=fid; this.functionName=name; this.status=status;
      this.pathResolution=res; this.parameterPositions=Collections.unmodifiableList(pos);
      this.steps=Collections.unmodifiableList(steps); this.hardSourceEligible=hard;
    }
    public String render(){
      StringBuilder b=new StringBuilder();
      b.append("ProvenancePath: function=").append(functionId).append(" name=").append(functionName)
       .append(" status=").append(status).append(" path_resolution=").append(pathResolution)
       .append(" positions=").append(parameterPositions)
       .append(" hard_source_eligible=").append(hardSourceEligible);
      for(Step s:steps) b.append("\n  STEP ").append(s.render());
      return b.toString();
    }
  }

  private static int rank(String r){
    if("UNRESOLVED".equals(r)||"UNKNOWN".equals(r)) return 3;
    if("AMBIGUOUS".equals(r)) return 2;
    if("HEURISTIC".equals(r)) return 1;
    return 0;
  }
  private static String weaker(String a,String b){ return rank(b)>rank(a)?b:a; }

  private static String varName(Expression e){
    if(!(e instanceof Variable)) return null;
    Expression ne=((Variable)e).getNameExpression();
    if(ne==null) return null;
    String s=ne.getEscapedCodeStr();
    return s==null?null:s.replace("\"","");
  }

  private static Expression uniqueRhs(String v,long fid){
    Expression rhs=null; int defs=0;
    for(ASTNode n:ASTUnderConstruction.idToNode.values()){
      Long nf; try{nf=n.getFuncId();}catch(Exception ex){continue;}
      if(nf==null||nf.longValue()!=fid||!(n instanceof AssignmentExpression)) continue;
      AssignmentExpression a=(AssignmentExpression)n;
      if(v.equals(varName(a.getLeft()))){ defs++; rhs=a.getRight(); if(defs>1)return null; }
    }
    return defs==1?rhs:null;
  }

  private static FunctionDef function(long fid){
    ASTNode n=ASTUnderConstruction.idToNode.get(fid);
    return n instanceof FunctionDef?(FunctionDef)n:null;
  }

  private static int parameterIndex(FunctionDef f,String v){
    ParameterList p=f==null?null:f.getParameterList();
    if(p==null)return -1;
    for(int i=0;i<p.size();i++) if(v.equals(((Parameter)p.getParameter(i)).getName())) return i;
    return -1;
  }

  private static String targetName(long t){
    FunctionDef f=function(t); return f==null?("fid:"+t):f.getName();
  }

  private static final class Trace {
    String resolution="EXACT";
    final LinkedHashSet<Integer> positions=new LinkedHashSet<Integer>();
    final ArrayList<Step> steps=new ArrayList<Step>();
    boolean uncertain=false;
  }

  private static void merge(Trace dst,Trace src){
    if(src==null)return;
    dst.resolution=weaker(dst.resolution,src.resolution);
    dst.positions.addAll(src.positions); dst.steps.addAll(src.steps); dst.uncertain|=src.uncertain;
  }

  private static Trace traceExpr(Expression e,long fid,FunctionDef f,int depth){
    Trace out=new Trace();
    if(e==null||depth>14){ out.resolution="UNKNOWN"; out.uncertain=true; return out; }

    String v=varName(e);
    if(v!=null && !(e instanceof CallExpressionBase)){
      int pi=parameterIndex(f,v);
      if(pi>=0){ out.positions.add(pi); out.steps.add(new Step("PARAM",e.getNodeId(),v,"EXACT")); return out; }
      Expression rhs=uniqueRhs(v,fid);
      if(rhs!=null){ out.steps.add(new Step("LOCAL_ASSIGN",e.getNodeId(),v,"EXACT")); merge(out,traceExpr(rhs,fid,f,depth+1)); return out; }
      out.steps.add(new Step("LOCAL_UNKNOWN",e.getNodeId(),v,"UNKNOWN")); out.resolution="UNKNOWN"; out.uncertain=true; return out;
    }

    if(e instanceof ConditionalExpression){
      ConditionalExpression c=(ConditionalExpression)e;
      Trace a=traceExpr(c.getTrueExpression(),fid,f,depth+1);
      Trace b=traceExpr(c.getFalseExpression(),fid,f,depth+1);
      out.steps.add(new Step("CONDITIONAL",e.getNodeId(),"branch join","AMBIGUOUS"));
      merge(out,a); merge(out,b); out.resolution=weaker(out.resolution,"AMBIGUOUS"); out.uncertain=true; return out;
    }

    if(e instanceof BinaryExpression){
      BinaryExpression b=(BinaryExpression)e;
      out.steps.add(new Step("BINARY",e.getNodeId(),e.getEscapedCodeStr()==null?"binary":e.getEscapedCodeStr(),"EXACT"));
      merge(out,traceExpr(b.getLeft(),fid,f,depth+1)); merge(out,traceExpr(b.getRight(),fid,f,depth+1)); return out;
    }

    if(e instanceof CallExpressionBase){
      CallExpressionBase c=(CallExpressionBase)e;
      List<Long> ts=PHPCGFactory.call2mtd.get(c.getNodeId());
      String cr=PHPCGFactory.frontendCallResolution.get(c.getNodeId());
      if(cr==null) cr=(ts!=null&&ts.size()==1)?"EXACT":(ts==null||ts.isEmpty()?"UNRESOLVED":"AMBIGUOUS");
      StringBuilder names=new StringBuilder();
      if(ts!=null) for(Long t:ts){ if(names.length()>0)names.append(','); names.append(targetName(t)); }
      out.steps.add(new Step("CALL",c.getNodeId(),names.length()==0?"unresolved":names.toString(),cr));
      out.resolution=weaker(out.resolution,cr); if(!"EXACT".equals(cr)) out.uncertain=true;
      if(ts==null||ts.isEmpty()){ out.resolution=weaker(out.resolution,"UNRESOLVED"); out.uncertain=true; return out; }
      ArgumentList al=c.getArgumentList(); if(al==null)return out;
      for(Long t:ts){
        String mr=PHPCGFactory.returnMayTaintResolution.get(t);
        if(mr!=null){
          out.steps.add(new Step("CALLEE_MAY_RETURN",t,targetName(t),mr));
          out.resolution=weaker(out.resolution,mr); out.uncertain=true;
          for(Integer p:PHPCGFactory.returnMayTaintPositions.getOrDefault(t,Collections.<Integer>emptySet()))
            if(p>=0&&p<al.size()) merge(out,traceExpr(al.getArgument(p),fid,f,depth+1));
        } else if(PHPCGFactory.returnTaintAnalyzed.contains(t)){
          out.steps.add(new Step("CALLEE_PROVEN_RETURN",t,targetName(t),"EXACT"));
          for(Integer p:PHPCGFactory.returnTaintPositions.getOrDefault(t,Collections.<Integer>emptySet()))
            if(p>=0&&p<al.size()) merge(out,traceExpr(al.getArgument(p),fid,f,depth+1));
        }
      }
      if(ts.size()>1){out.resolution=weaker(out.resolution,"AMBIGUOUS"); out.uncertain=true;}
      return out;
    }

    out.steps.add(new Step("VALUE",e.getNodeId(),e.getEscapedCodeStr()==null?e.getClass().getSimpleName():e.getEscapedCodeStr(),"EXACT"));
    return out;
  }

  /** Compatibility projection for consumers that still expect a hard source-path string.
   * Uncertain paths are structurally ineligible and return empty. */
  public static java.util.Optional<String> hardSourceProjection(Path p){
    if(p==null || !p.hardSourceEligible) return java.util.Optional.empty();
    return java.util.Optional.of("HARD_PROVENANCE_PATH function="+p.functionId+" positions="+p.parameterPositions);
  }

  public static Path forFunction(long fid){
    FunctionDef f=function(fid);
    String name=f==null?("fid:"+fid):f.getName();
    ProvenanceEvidenceReporter.Record ev=ProvenanceEvidenceReporter.forFunction(fid);
    Trace best=null;
    for(ASTNode n:ASTUnderConstruction.idToNode.values()){
      Long nf; try{nf=n.getFuncId();}catch(Exception ex){continue;}
      if(nf==null||nf.longValue()!=fid||!(n instanceof ReturnStatement))continue;
      Expression re=((ReturnStatement)n).getReturnExpression();
      Trace t=traceExpr(re,fid,f,0);
      t.steps.add(0,new Step("RETURN",n.getNodeId(),re==null?"":String.valueOf(re.getEscapedCodeStr()),t.resolution));
      if(best==null || rank(t.resolution)>rank(best.resolution) || t.steps.size()>best.steps.size()) best=t;
    }
    if(best==null) best=new Trace();
    String finalRes=best.resolution;
    if(ev.status==ProvenanceEvidenceReporter.Status.MAY) finalRes=weaker(finalRes,ev.resolution);
    if(ev.status==ProvenanceEvidenceReporter.Status.UNKNOWN) finalRes="UNKNOWN";
    ArrayList<Integer> pos=new ArrayList<Integer>(ev.parameterPositions); Collections.sort(pos);
    boolean hard=ev.hardSource && "EXACT".equals(finalRes) && !best.uncertain;
    return new Path(fid,name,ev.status.name(),finalRes,pos,best.steps,hard);
  }
}
