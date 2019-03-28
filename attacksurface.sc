import io.circe.Json
import io.circe.syntax._
import io.circe.generic.auto._
import io.shiftleft.libsecurityprofile.{SpLoader, SpPrimitives}

def getAttackSurface(sp: SpPrimitives) {


    import io.shiftleft.libsecurityprofile.domain.types.Route.Defined
    
    case class Vulnerability(route: String, owaspCategories: List[String], title: String, description: String, name: String, paramtype: String)
    case class AttackSurface(appName : String, vulnerabilites: List[Vulnerability])
    
    val vulns = sp.conclusions.l.flatMap { conclusion => 
        conclusion.ioFlows.l.flatMap { ioFlow => 
            ioFlow.sourceHttpRoutes.collect { case Defined(route) => 
            Vulnerability(route, conclusion.categories, conclusion.title, conclusion.description, conclusion.ioFlows.primaryFlow.elements.head.parameter.l.head.name, conclusion.ioFlows.primaryFlow.elements.head.parameter.l.head.evalType)
            }
        }
    
    }

    val attackSurface = AttackSurface("attack-surface", vulns)

    val outData = attackSurface.asJson.spaces2
    println(outData)
}