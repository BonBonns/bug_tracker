@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  def cl(s:String)=Option(s).getOrElse("").replace("\n"," ").take(60)
  println("=== how ESM imports LOWER (app.ts assignments) ===")
  cpg.method.l.filter(_.filename=="app.ts").flatMap(_.ast.isCall.nameExact("<operator>.assignment").l).map(a=>cl(a.code)).distinct.foreach{c=>println(s"  $c")}
  println("=== require() calls: is inAssignment the binding? (R14's assumption) ===")
  cpg.call.nameExact("require").l.filter(_.method.filename=="app.ts").foreach{c=>
    println(s"  ${cl(c.code)}  inAssignment=[${c.inAssignment.l.map(x=>cl(x.code)).mkString(" ; ")}]")}
  println("=== dynamic import() representation ===")
  cpg.call.l.filter(c=>c.code.contains("import(")).map(c=>s"${c.name} | ${cl(c.code)}").distinct.take(4).foreach{c=>println(s"  $c")}
}
