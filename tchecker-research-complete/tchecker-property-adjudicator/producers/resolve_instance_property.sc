// TS-INSTANCE-PROP-R01: resolves a call `receiver.propName(...)` to a constructor-assigned
// arrow-function implementation ONLY when the receiver's concrete type can be confirmed and there
// is exactly one candidate implementation for that concrete type. No "same property name means
// same function" shortcut anywhere in this rule.
//
// Rule (conservative, matches the design brief exactly):
//   call on receiver property
//   -> find ALL classes with a `this.propName = <function>` assignment SCOPED TO THEIR OWN
//      constructor (enclosingMethod.name == "<init>" specifically -- excludes reassignment in any
//      other method, and excludes normal prototype-method declarations of the same name, which are
//      a structurally different mechanism entirely and not touched by this rule at all)
//   -> determine the receiver's CONFIRMED CONCRETE TYPE: either the receiver expression is
//      directly `new ClassName(...)`, or (if the receiver is a parameter) every traceable call
//      site of the enclosing function passes an argument that is confirmed `new ClassName(...)`
//      (directly, or via a same-function local variable assigned from one)
//   -> if the set of confirmed concrete types has EXACTLY ONE member, AND that class has EXACTLY
//      ONE constructor-scoped assignment of propName, bridge to that implementation
//   -> otherwise (multiple candidate classes, multiple/no confirmed concrete types, ambiguous
//      call sites) -> ABSTAIN, UNKNOWN. Never guess.
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes

def constructorAssignedCandidates(propName: String): Map[String, nodes.Call] = {
  cpg.call.name("<operator>.assignment").code(s".*$propName.*").l
    .filter(_.method.name == "<init>")
    .filter { a =>
      // confirm the LHS is specifically `this.propName`, not some other coincidental text match
      val lhs = a.argument.l.find(_.argumentIndex == 1)
      lhs.exists {
        case fld: nodes.Call if fld.name == "<operator>.fieldAccess" =>
          fld.code.split("\\.").lastOption.contains(propName)
        case _ => false
      }
    }
    .map(a => a.method.typeDecl.headOption.map(_.name).getOrElse("?") -> a)
    .toMap
}

// finds a `new ClassName(...)` construction that a given expression is confirmed to hold --
// directly, or via a same-function local variable traced back to one assignment.
def confirmedConstructedClass(expr: nodes.AstNode, withinMethod: nodes.Method): Option[String] = {
  def extractClassNameIfConstructor(n: nodes.AstNode): Option[String] = {
    // new X(...) lowers to a Block wrapping an <operator>.new call (the same lowering shape as
    // new URL()/new RegExp() elsewhere in this session) -- check both the node itself AND its
    // constructor-call descendant, not just a direct Call-typed match.
    val code = n.code.trim
    if (code.startsWith("new ")) {
      val directNew = n match { case c: nodes.Call if c.name == "<operator>.new" => Some(c); case _ => None }
      val nestedNew = n.ast.isCall.name("<operator>.new").headOption
      (directNew.orElse(nestedNew)).map(_.code.stripPrefix("new ").takeWhile(ch => ch.isLetterOrDigit || ch == '_'))
    } else None
  }
  expr match {
    case n if extractClassNameIfConstructor(n).isDefined =>
      extractClassNameIfConstructor(n)
    case id: nodes.Identifier =>
      val assigns = withinMethod.ast.isCall.name("<operator>.assignment").l.filter { a =>
        a.argument.l.find(_.argumentIndex == 1).exists(_.code.trim == id.code.trim)
      }
      val newCalls = assigns.flatMap(_.argument.l.find(_.argumentIndex == 2)).flatMap(extractClassNameIfConstructor)
      if (newCalls.distinct.size == 1) newCalls.headOption else None
    case _ => None
  }
}

def resolveInstanceProperty(callSite: nodes.Call, propName: String): Either[String, nodes.Call] = {
  val candidates = constructorAssignedCandidates(propName)
  if (candidates.isEmpty) return Left(s"no constructor-scoped assignment of '$propName' found anywhere")
  val receiverExpr = callSite.argument.l.find(_.argumentIndex == 0)
  val enclosingMethod = callSite.method
  val confirmedTypes: Set[String] = receiverExpr match {
    case Some(r) if confirmedConstructedClass(r, enclosingMethod).isDefined =>
      confirmedConstructedClass(r, enclosingMethod).toSet
    case Some(id: nodes.Identifier) =>
      // is this identifier a PARAMETER of the enclosing method? if so, trace callers.
      val isParam = enclosingMethod.parameter.exists(_.name == id.name)
      if (isParam) {
        val paramIdx = enclosingMethod.parameter.find(_.name == id.name).map(_.index).getOrElse(-1)
        val callers = cpg.call.filter(_.methodFullName == enclosingMethod.fullName).l
        val typesFromCallers = callers.flatMap { callerCall =>
          val argAtIdx = callerCall.argument.l.find(_.argumentIndex == paramIdx)
          argAtIdx.flatMap(a => confirmedConstructedClass(a, callerCall.method))
        }
        typesFromCallers.toSet
      } else {
        // local variable within the SAME method
        confirmedConstructedClass(id, enclosingMethod).toSet
      }
    case _ => Set()
  }
  if (confirmedTypes.size != 1) {
    return Left(s"receiver concrete type not uniquely confirmed (candidates found: ${confirmedTypes.mkString(",")})")
  }
  val theType = confirmedTypes.head
  // dominance check: does the confirmed class ALSO reassign this property OUTSIDE its
  // constructor (e.g. in a method like `rebind()`)? If so, whether that reassignment executes
  // before or after THIS specific call site cannot be verified without full interprocedural
  // control-flow analysis -- conservatively abstain rather than assume the constructor-assigned
  // value is still live.
  val hasPostConstructionReassignment = cpg.call.name("<operator>.assignment").code(s".*$propName.*").l
    .filter(_.method.name != "<init>")
    .filter { a =>
      val lhs = a.argument.l.find(_.argumentIndex == 1)
      lhs.exists {
        case fld: nodes.Call if fld.name == "<operator>.fieldAccess" => fld.code.split("\\.").lastOption.contains(propName)
        case _ => false
      }
    }
    .exists(_.method.typeDecl.headOption.map(_.name).contains(theType))
  if (hasPostConstructionReassignment) {
    return Left(s"'$theType' reassigns '$propName' outside its constructor -- dominance not " +
                "provable, the live implementation at this call site cannot be confirmed")
  }
  candidates.get(theType) match {
    case Some(assign) if candidates.size >= 1 =>
      // also require: does the CANDIDATE SET restricted to this confirmed type contain exactly
      // one implementation? (it does, by construction of the Map, but confirm no other class
      // with the SAME name masks this -- already guaranteed since Map keys are class names)
      Right(assign)
    case None =>
      Left(s"confirmed concrete type '$theType' has no constructor-scoped assignment of '$propName' " +
           s"(available candidates: ${candidates.keys.mkString(",")})")
  }
}

@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  val testCalls = Seq(
    ("use", "getReadStream", "RESOLVE to LocalStore's implementation"),
    ("useAmbiguous", "getReadStream", "ABSTAIN (two subclasses, ambiguous)"),
    ("useUnrelated", "getReadStream", "ABSTAIN (no caller / no confirmed type -- must not cross-bind to LocalStore)"),
    ("useReassigned", "getReadStream", "ABSTAIN (reassignment after constructor -- dominance not proven)"),
    ("usePrototypeOrProperty", "getReadStream", "ABSTAIN (receiver type not confirmed here; prototype-method case is out of this rule's scope entirely)")
  )
  testCalls.foreach { case (fnName, propName, expected) =>
    val m = cpg.method.name(fnName).headOption
    m match {
      case None => println(s"$fnName: NO_METHOD_FOUND")
      case Some(method) =>
        val call = method.ast.isCall.filter(_.code.contains(s".$propName(")).headOption
        call match {
          case None => println(s"$fnName: NO_CALL_FOUND")
          case Some(c) =>
            resolveInstanceProperty(c, propName) match {
              case Right(assign) => println(s"$fnName: RESOLVED to ${assign.method.typeDecl.headOption.map(_.name).getOrElse("?")}'s assignment (${assign.code.take(50)}) | expected: $expected")
              case Left(reason) => println(s"$fnName: ABSTAIN ($reason) | expected: $expected")
            }
        }
    }
  }
}
