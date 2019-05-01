import $ivy.`com.lihaoyi::requests:0.1.7`
import $ivy.`com.47deg::github4s:0.20.1`

import io.shiftleft.codepropertygraph.generated.nodes
import github4s.Github
import github4s.Github._
import github4s.jvm.Implicits._
import scalaj.http.HttpResponse
import scala.collection.mutable.ListBuffer


def createIssueInGitHub(issue : String, accessToken : Option[String], owner : String, repoName : String, title: String) = {
  
      val createIssue = Github(accessToken).issues.createIssue(owner, repoName, title, issue)
      createIssue.exec[cats.Id, HttpResponse[String]]() match {
            case Left(e) => println(s"Something went wrong: ${e.getMessage}")
            case Right(r) => println(r.result)
      }
}


