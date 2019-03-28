import io.shiftleft.codepropertygraph.generated.nodes
import github4s.jvm.Implicits._
import scala.collection.mutable.ListBuffer
import io.circe.Json
import io.circe.syntax._
import io.circe.generic.auto._

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



