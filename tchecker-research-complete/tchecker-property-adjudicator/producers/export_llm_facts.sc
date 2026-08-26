// JS-PROV-LLM1 — LLM-input vulnerability fact producer.
//
// Two shapes from the OWASP LLM Top-10:
//   LLM02 Insecure Output Handling — model output flows into a code/command/
//         HTML/SQL sink (eval, exec, res.send, a SQL query) without validation.
//   LLM01 Prompt Injection — untrusted request data flows into the SYSTEM
//         instruction position of an LLM call (instruction override).
//
// Fact files (separate, opt-in — R33 rule):
//   llm_call_sites.tsv  file, method, line, provider, result_local
//   llm_output_sinks.tsv  file, method, line, sink_kind, fed_by_llm, in_try_catch
//       sink_kind in {EVAL, EXEC, SQL, HTML_RESPONSE, REDIRECT}.
//   prompt_injection.tsv  file, method, line, role, request_tainted
//       role in {system, user}. request_tainted = request data reaches the
//       role's content.
import io.shiftleft.codepropertygraph.generated.nodes

@main def exec(cpgFile: String, outDir: String) = {
  importCpg(cpgFile); new java.io.File(outDir).mkdirs()
  def cl(s: String) = Option(s).getOrElse("").replace("\n", " ").replace("\t", " ").take(200)
  def w(n: String) = new java.io.PrintWriter(new java.io.File(s"$outDir/$n"), "UTF-8")

  // request/untrusted sources (Express/Koa/Hapi/Fastify), reused from serialize.
  def attackerCode(code: String): Boolean =
    code.matches("""(?s).*\breq(uest)?\.body\b.*""") ||
    code.matches("""(?s).*\bctx\.request\.body\b.*""") ||
    code.matches("""(?s).*\brequest\.(payload|query|params)\b.*""") ||
    code.matches("""(?s).*\breq\.(query|params|body)\b.*""")

  // Per-file imports, to disambiguate messages.create (Anthropic) from
  // Twilio's messages.create (SMS). Built from require()/import RHS.
  val fileImports = scala.collection.mutable.Map[String, scala.collection.mutable.Set[String]]()
  cpg.call.l.foreach { c =>
    val code = Option(c.code).getOrElse("")
    if (code.matches("""(?s).*\brequire\s*\(.*""") || code.matches("""(?s).*\bimport\b.*""")) {
      val f = c.method.filename
      fileImports.getOrElseUpdate(f, scala.collection.mutable.Set()) += code.toLowerCase
    }
  }
  def fileHasAnthropic(file: String): Boolean =
    fileImports.get(file).exists(_.exists(s =>
      s.contains("@anthropic-ai") || s.matches("""(?s).*\brequire\s*\(\s*['"]anthropic['"].*""") ||
      s.contains("anthropic/sdk")))
  // Does a `messages.create` call carry a `model:` member? (Anthropic yes,
  // Twilio no — Twilio uses body/to/from.)
  def callHasModelArg(c: nodes.Call): Boolean =
    c.argument.l.exists { a =>
      a.ast.isCall.name("<operator>.fieldAccess").exists { fa =>
        fa.argument.l.find(_.argumentIndex == 2).exists(x => Option(x.code).getOrElse("") == "model")
      }
    }

  // KNOWN_LLM_HTTP_DOMAINS: provider API domains reachable only via a generic HTTP client
  // (RocketChat's IHttp.post/get, or a bespoke fetch wrapper) rather than a named SDK. Confirmed
  // necessary by scanning a real, deployed RocketChat plugin (Rocket.Chat.App-Gemini) that calls
  // Google's Gemini API via http.post(url, ...) with the URL built separately -- the prior
  // recognition logic (SDK-name and fetch()-to-openai/anthropic patterns only) produced zero
  // facts for this genuine LLM call site, a real gap, not a false alarm avoided.
  val KNOWN_LLM_HTTP_DOMAINS = List("generativelanguage.googleapis.com", "api.openai.com",
    "api.anthropic.com", "api.cohere.ai", "api.mistral.ai")
  def resolvesToKnownLlmDomain(c: nodes.Call): Boolean = {
    val urlArg = c.argument.l.find(_.argumentIndex == 1)
    urlArg.exists { arg =>
      // direct literal/template-literal in the call itself
      val directMatch = KNOWN_LLM_HTTP_DOMAINS.exists(d => Option(arg.code).getOrElse("").contains(d))
      // OR traced through a same-method `const url = ...` assignment (RocketChat's http.post(url,
      // ...) pattern builds the URL separately, not inline)
      val tracedMatch = c.method.ast.isCall.name("<operator>.assignment").l.exists { a =>
        val lhsMatches = a.argument.l.find(_.argumentIndex == 1).exists(_.code.trim == arg.code.trim)
        val rhsHasDomain = a.argument.l.find(_.argumentIndex == 2)
          .exists(rhs => KNOWN_LLM_HTTP_DOMAINS.exists(d => Option(rhs.code).getOrElse("").contains(d)))
        lhsMatches && rhsHasDomain
      }
      directMatch || tracedMatch
    }
  }

  // An LLM completion call: provider SDK create/invoke, AI-SDK generateText,
  // or a raw fetch to a provider endpoint.
  def llmProvider(c: nodes.Call): Option[String] = {
    val code = Option(c.code).getOrElse("")
    if (code.matches("""(?s).*chat\.completions\.create.*""") ||
        code.matches("""(?s).*completions\.create.*""")) Some("openai")
    else if (code.matches("""(?s).*messages\.create.*""") &&
             (fileHasAnthropic(c.method.filename) || callHasModelArg(c))) Some("anthropic")
    else if (code.matches("""(?s).*\b(generateText|streamText|generateObject)\s*\(.*""")) Some("ai-sdk")
    else if (Set("post", "get").contains(c.name) &&
             resolvesToKnownLlmDomain(c)) Some("generic-http-llm")
    else if (code.matches("""(?s).*\.(invoke|call)\s*\(.*""") &&
             code.matches("""(?s).*\b(llm|chain|model|chat)\b.*""")) Some("langchain")
    else if (code.matches("""(?s).*fetch\s*\([^)]*api\.(openai|anthropic)\.com.*""")) Some("fetch-llm")
    else None
  }
  // output accessor on an LLM result
  def isLlmOutputAccess(code: String): Boolean =
    code.matches("""(?s).*\.choices\b.*""") ||
    code.matches("""(?s).*message\.content\b.*""") ||
    code.matches("""(?s).*\.content\[.*""") ||
    code.matches("""(?s).*\.content\b.*""") && code.matches("""(?s).*\.text\b.*""") ||
    code.matches("""(?s).*\.content\[0\]\.text\b.*""")

  // ---- llm_call_sites.tsv + result locals ----------------------------------
  val cs = w("llm_call_sites.tsv")
  // map (file,method) -> set of local names holding an LLM result
  val resultLocals = scala.collection.mutable.Map[String, scala.collection.mutable.Set[String]]()
  try cpg.call.l.foreach { c =>
    llmProvider(c).foreach { prov =>
      if (c.name == "create" || c.name == "generateText" || c.name == "streamText" ||
          c.name == "generateObject" || c.name == "invoke" || c.name == "call" || c.name == "fetch" ||
          c.name == "post" || c.name == "get") {
        val m = c.method
        // find the local the result is assigned to (climb to enclosing assignment)
        val assign = c.inAst.collectAll[nodes.Call].l.find(_.name == "<operator>.assignment")
        val resultLocal = assign.flatMap(_.argument.l.find(_.argumentIndex == 1).collect {
          case i: nodes.Identifier => i.name
        })
        resultLocal.foreach { rl =>
          resultLocals.getOrElseUpdate(m.filename + "\u0001" + m.fullName, scala.collection.mutable.Set()).add(rl)
        }
        cs.println(Seq(cl(m.filename), cl(m.fullName),
          c.lineNumber.map(_.toString).getOrElse(""), prov,
          cl(resultLocal.getOrElse(""))).mkString("\t"))
      }
    }
  } finally cs.close()

  // ---- llm_output_sinks.tsv ------------------------------------------------
  val os = w("llm_output_sinks.tsv")
  def sinkKind(c: nodes.Call): Option[String] = {
    val code = Option(c.code).getOrElse("")
    if (c.name == "eval" || code.matches("""(?s).*\bnew Function\b.*""") || c.name == "Function") Some("EVAL")
    else if (Set("exec","execSync","spawn","spawnSync").contains(c.name)) Some("EXEC")
    else if (c.name == "query" || code.matches("""(?s).*\.(query|raw)\s*\(.*""")) Some("SQL")
    else if (code.matches("""(?s).*\bres\.(send|write|end)\s*\(.*""") ||
             code.matches("""(?s).*\.type\s*\(\s*['"]text/html.*""")) Some("HTML_RESPONSE")
    else if (code.matches("""(?s).*\bres\.redirect\s*\(.*""")) Some("REDIRECT")
    else None
  }
  try cpg.method.isExternal(false).l.foreach { m =>
    val key = m.filename + "\u0001" + m.fullName
    val rls = resultLocals.getOrElse(key, scala.collection.mutable.Set())
    // locals that hold LLM output: assigned from an LLM result local or an
    // output accessor.
    val outputLocals = scala.collection.mutable.Set[String]()
    m.assignment.l.foreach { a =>
      val rhs = a.argument.l.find(_.argumentIndex == 2).map(x => Option(x.code).getOrElse("")).getOrElse("")
      val lhs = a.argument.l.find(_.argumentIndex == 1).collect { case i: nodes.Identifier => i.name }
      val fromLlm = isLlmOutputAccess(rhs) && rls.exists(rl => rhs.matches(s"""(?s).*\\b${java.util.regex.Pattern.quote(rl)}\\b.*""")) ||
        outputLocals.exists(o => rhs.matches(s"""(?s).*\\b${java.util.regex.Pattern.quote(o)}\\b.*"""))
      if (fromLlm) lhs.foreach(outputLocals += _)
    }
    m.call.l.foreach { c =>
      sinkKind(c).foreach { k =>
        val argCode = c.argument.l.filter(_.argumentIndex >= 1).map(a => Option(a.code).getOrElse("")).mkString(" ")
        val fedByLlm = outputLocals.exists(o => argCode.matches(s"""(?s).*\\b${java.util.regex.Pattern.quote(o)}\\b.*""")) ||
          (isLlmOutputAccess(argCode) && rls.exists(rl => argCode.matches(s"""(?s).*\\b${java.util.regex.Pattern.quote(rl)}\\b.*""")))
        val inTry = c.inAst.collectAll[nodes.ControlStructure].l.exists(_.controlStructureType == "TRY")
        os.println(Seq(cl(m.filename), cl(m.fullName),
          c.lineNumber.map(_.toString).getOrElse(""), k, fedByLlm.toString, inTry.toString).mkString("\t"))
      }
    }
  } finally os.close()

  // ---- prompt_injection.tsv ------------------------------------------------
  // Within an LLM call's argument object, a `system:` (or system-role message)
  // whose value is request-tainted.
  val pi = w("prompt_injection.tsv")
  try cpg.call.l.foreach { c =>
    llmProvider(c).foreach { _ =>
      // object-literal members assigned into the call's argument temp
      val m = c.method
      // find assignments of the form `_tmp.system = <expr>` near this call
      m.assignment.l.foreach { a =>
        val lhsC = a.argument.l.find(_.argumentIndex == 1).map(x => Option(x.code).getOrElse("")).getOrElse("")
        val rhsC = a.argument.l.find(_.argumentIndex == 2).map(x => Option(x.code).getOrElse("")).getOrElse("")
        val roleOpt =
          if (lhsC.matches("""(?s).*\.system\b.*""")) Some("system")
          else if (rhsC.matches("""(?s).*role['":\s]+system.*""")) Some("system")
          else None
        roleOpt.foreach { role =>
          val tainted = attackerCode(rhsC)
          if (tainted)
            pi.println(Seq(cl(m.filename), cl(m.fullName),
              a.lineNumber.map(_.toString).getOrElse(""), role, tainted.toString).mkString("\t"))
        }
      }
    }
  } finally pi.close()

  println(s"LLM1_FACTS_COMPLETE: $outDir")
}
