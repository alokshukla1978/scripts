import $ivy.`com.softwaremill.sttp::core:1.5.11`
import $ivy.`com.47deg::github4s:0.20.1`
import $ivy.`org.json4s::json4s-jackson:3.6.5`

import com.softwaremill.sttp.quick._

import org.json4s._
import org.json4s.jackson.JsonMethods._
import org.json4s.JsonDSL._
import org.json4s.jackson.Serialization._
import org.json4s.native.Serialization.writePretty
import com.softwaremill.sttp.quick._

object Get {
    def string(value: JValue): String = {
      val JString(result) = value
      result
    }
}

case class CVEDetails(id : String, cwe : String, description : String)
case class SoftwareComposition(name : String, version : String, cvDetails : Option[List[CVEDetails]])


def getCve(deps : List[(String, String)]) = {
    implicit val jsonFormats = DefaultFormats
    deps.map {
        dep =>
           val searchString = StringBuilder.newBuilder
           var depVer = searchString.append(dep._1).append(":").append(dep._2).toString
           println("Processing OSS Dependency : " + depVer)
           val r = sttp.get(uri"http://cve.circl.lu/api/search/fasterxml/$depVer").send()
           if(r.isSuccess) {
               val json = parse(r.unsafeBody)
               val cve = json \\ "id" \\ classOf[JString] map (Get.string(_)) 
               val cwe = json \\ "cwe" \\ classOf[JString] map (Get.string(_)) 
               val summary = json \\ "summary" \\ classOf[JString] map (Get.string(_))
               val cveDetails = cve zip cwe zip summary map { case ((a,b),c) => (a,b,c) } map { item => CVEDetails(item._1, item._2, item._3) }
               val sca = SoftwareComposition(dep._1,dep._2,Some(cveDetails))
               writePretty(sca)
           } else {
               val sca = SoftwareComposition(dep._1,dep._2,None)
               writePretty(sca)
           }
    }
}

