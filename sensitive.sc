import io.shiftleft.codepropertygraph.generated.nodes
import github4s.jvm.Implicits._
import scala.collection.mutable.ListBuffer
import io.shiftleft.libsecurityprofile.SpPrimitives
import io.circe.Json
import io.circe.syntax._
import io.circe.generic.auto._

def isSensitiveDataLeaking(sp : SpPrimitives) = {
  sp.conclusions.title(".*sensitive-to-log.*").flows
}

def getSensitiveClassesMap(sp: SpPrimitives): Map[String, Seq[String]] = {
  def isKnownPkgName(pkgName: String): Boolean =
    pkgName.startsWith("org.java") || pkgName.startsWith("java") || pkgName.startsWith("javax")

  val typPairs =
    for {
      typ      <- sp.getSensitiveData.types
      category <- typ.categories()
      typAsString = s"${typ.fullName}"
    } yield typAsString -> category

  typPairs
    .groupBy(_._1)
    .mapValues(_.map(_._2))
}

case class FlowTrace(methodName :String, parameter :String,fileName :String, linNumber :String)

def locations(flow: nodes.NewFlow): List[nodes.NewLocation] =
     flow.points.map(_.elem.location.asInstanceOf[nodes.NewLocation])

def getFlowTrace(flows: dataflows.steps.NewFlow[shapeless.HNil]): String = {
  val flow = flows.head
  val locs: List[nodes.NewLocation] = locations(flow)
  val f = locs.map { location =>
    val line = location.lineNumber.getOrElse("SYSTEM")
    FlowTrace(location.methodShortName,location.symbol,location.filename,line.toString)
  }
  f.asJson.spaces2
}

def printLeakingData(sensitiveType : String) = {
    val source = cpg.local.evalType(sensitiveType).referencingIdentifiers
    val sink = cpg.method.fullName(".*Logger.*").parameter
    val flows = sink.reachableBy(source).flows
    getFlowTrace(flows)
}
