// rv-joern taint: data flows from untrusted input to dangerous sinks, as JSON.
// Usage: joern --script /opt/kali-mcp/joern/taint.sc --param src=/src/app --param out=joern-flows.json
// Language is auto-detected by Joern. Patterns are name/code heuristics, so review every flow.
import io.shiftleft.semanticcpg.language.*
import io.joern.dataflowengineoss.language.*

val SourceCode = ("(?is).*(" + List(
  "request\\.(args|form|values|data|json|get_json|cookies|headers|files|stream|body|query|params|GET|POST|FILES|COOKIES|META)",
  "getParameter|getHeader|getQueryString|getInputStream|getReader|getCookies|@RequestParam|@PathVariable|@RequestBody",
  "req\\.(query|body|params|headers|cookies)", "\\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)",
  "os\\.environ|getenv|sys\\.argv|process\\.argv|process\\.env|\\binput\\(", "r\\.(URL\\.Query|FormValue|PostFormValue|Body)"
).mkString("|") + ").*").r

val SinkName = ("(?i)(" + List(
  "execute|executemany|executescript|executeQuery|executeUpdate|prepareStatement|createQuery|createNativeQuery|raw|rawQuery",
  "system|popen|check_output|check_call|Popen|spawn|execSync|execFile|exec_command|getRuntime|ProcessBuilder|shell_exec|passthru|proc_open",
  "eval|exec|compile|unsafe_load|readObject|deserialize|unserialize|pickle_loads",
  "render_template_string|Template|from_string|innerHTML|dangerouslySetInnerHTML|document_write",
  "send_file|send_from_directory|readFile|readFileSync|createReadStream|sendFile|include|require_once",
  "redirect|sendRedirect|urlopen|urlretrieve"
).mkString("|") + ")").r
// generic names (load, open, get, call, run, ...) count only with a dangerous receiver/module in the code
val SinkCode = ("(?is).*(" + List(
  "yaml\\.load\\(", "pickle\\.loads?\\(", "marshal\\.loads?\\(", "shelve\\.open\\(", "subprocess\\.(run|call)\\(",
  "os\\.(system|popen|exec\\w*)\\(", "\\bopen\\(", "requests\\.(get|post|put|patch|delete|request)\\(",
  "httpx\\.(get|post|request)\\(", "axios\\.(get|post|request)\\(", "\\bfetch\\(", "http\\.Get\\(", "exec\\.Command\\(",
  "db\\.(Query|Exec)\\(", "child_process"
).mkString("|") + ").*").r

def loc(n: io.shiftleft.codepropertygraph.generated.nodes.AstNode) = {
  val l = n.location
  ujson.Obj("file" -> l.filename, "line" -> ujson.Num(l.lineNumber.getOrElse(-1).toDouble),
            "method" -> l.methodShortName, "code" -> n.code.take(200))
}

@main def exec(src: String, out: String = "joern-flows.json", max: Int = 100) = {
  importCode(inputPath = src, projectName = "rv-taint")
  val sources = cpg.call.filter(c => SourceCode.matches(c.code)).l ++
                cpg.parameter.filter(p => SourceCode.matches(p.code) || p.annotation.name("Request.*|PathVariable").nonEmpty).l
  val sinkCalls = cpg.call.filter(c => SinkName.matches(c.name) || SinkCode.matches(c.code))
                     .filterNot(_.name.startsWith("<operator>")).l   // sinks may contain input inline: yaml.load(request.data)
  val flows = sinkCalls.argument.reachableByFlows(sources).l
  val seen = scala.collection.mutable.Set[String]()
  val rows = flows.flatMap { f =>
    val els = f.elements
    val (s, k) = (els.head, els.last)
    val key = s"${s.location.filename}:${s.location.lineNumber}->${k.location.filename}:${k.location.lineNumber}"
    if (seen.add(key)) Some(ujson.Obj(
      "source" -> loc(s), "sink" -> loc(k),
      "sink_call" -> (k match { case e: io.shiftleft.codepropertygraph.generated.nodes.Expression => e.inCall.headOption.map(_.code).getOrElse(e.code); case o => o.code }).take(200),
      "path" -> ujson.Arr(els.map(loc)*))) else None
  }.take(max)
  val result = ujson.Obj("target" -> src, "sources_found" -> ujson.Num(sources.size.toDouble),
                         "sinks_found" -> ujson.Num(sinkCalls.size.toDouble), "flows" -> ujson.Arr(rows*))
  os.write.over(os.Path(out, os.pwd), ujson.write(result, indent = 1))
  println(s"rv-joern taint: ${sources.size} sources, ${sinkCalls.size} sinks, ${rows.size} flows -> $out")
}
