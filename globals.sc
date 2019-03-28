// imports of 3rd party integration API
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


def getCve(cpg: io.shiftleft.queryprimitives.steps.starters.Cpg) = {
    implicit val jsonFormats = DefaultFormats
    val deps = cpg.dependency.l.map { d => Tuple2(d.name,d.version) }
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


//harcoded patterns 
val awsAccess = "\"[0-9a-zA-Z/+]{40}\""
val awsSecret = "\"AKIA[0-9A-Z]{16}\""
val javaLogger = ".*Logger.*info.*"

//Your GitHib information 
val accessToken = Some("XXXXXX")
val owner = "XXXXX"
val reponame = "XXXXX"

def getDependencies(cpg: io.shiftleft.queryprimitives.steps.starters.Cpg) = {
    cpg.dependency.l.map(d => (d.name, d.version)).distinct
}

def getApiFunctions(cpg: io.shiftleft.queryprimitives.steps.starters.Cpg) = {
    cpg.method.parameter.evalType(".*HttpServletRequest.*").method.filterNot(_.callIn).fullName.p
}

// Sources
// -------

val httpSources = ".*HttpServletRequest.*|.*javax.servlet.http.HttpServletRequest.(getAuthType|getHeader|getHeaders|getMethod|getPathInfo|getPathTranslated|getContextPath|getQueryString|getRemoteUser|getRequestedSessionId|getRequestURI|getRequestURL|getServletPath|getAttribute|getAttributeNames|getCharacterEncoding|getContentType|getParameter|getParameterNames|getParameterValues|getParameterMap|getProtocol|getScheme|getServerName|getRemoteAddr|getRemoteHost|getLocalName|getLocalAddr|getReader).*"

val servletSources = ".*javax.servlet.ServletRequest.(getAttribute|getAttributeNames|getCharacterEncoding|getContentType|getParameter|getParameterNames|getParameterValues|getParameterMap|getProtocol|getScheme|getServerName|getRemoteAddr|getRemoteHost|getLocalName|getLocalAddr|getReader).*"

val servletContextSources = ".*javax.servlet.ServletContext.(getResourceAsStream|getRealPath|getHeaderNames).*"

val genericServletSources = ".*javax.servlet.GenericServlet.(getInitParameter|getInitParameterNames).*"

val cookieSources = ".*javax.servlet.http.Cookie.(getComment|getDomain|getPath|getName|getValue).*"

val servletConfigSources = ".*javax.servlet.ServletConfig.(getInitParameter|getInitParameterNames).*"

val sqlResultSet = ".*java.sql.ResultSet.(getString|getObject).*"

val awtSources = ".*java.awt.TextComponent.(getSelectedText|getText).*"

val consoleSources = ".*java.io.Console.(readLine|readPassword).*"

val inputStreamSources = ".*java.io.DataInputStream.(readLine|readUTF).*"

val linReaderSources = ".*java.io.LineNumberReader.(readLine).*"

val httpSessionSources = ".*javax.servlet.http.HttpSession.(getAttribute|getAttributeNames|getValue|getValueNames).*"

val systemSources = ".*java.lang.System.(getProperty|getProperties|getenv).*"

val propertySources = ".*java.util.Properties.(getProperty).*"

val resourceSources = ".*java.lang.Class.(getResource|getResourceAsStream).*"

val xmlRpcSources = ".*org.apache.xmlrpc.XmlRpcClient.(execute|search).*"

val xpathSources = ".*javax.xml.xpath.XPath.(evaluate).*"

val xpathExprSources = ".*javax.xml.xpath.XPathExpression.(evaluate).*"

val randSource = ".*java.security.SecureRandom.(<init>).*|.*java.util.Random.(<init>).*"

val fileSource = ".*javax.tools.SimpleJavaFileObject.*|.*java.io.File.(<init>).*"

val connectionPoolSources = "org.apache.commons.dbcp2|com.zaxxer.HikariCP|com.mchange.c3p0"


// Initializers
// ------------

val connectionPoolInitializers = ".*ComboPooledDataSource.*(setDriverClass|setJdbcUrl|setUser|setPassword|setMinPoolSize|setAcquireIncrement|setMaxPoolSize).*"
val dbInitializers = ".*HikariConfig.*<init>.*|.*java.sql.Connection.close.*"

// Sanitizers
// ----------

val esapiSantizers = "org.owasp.encoder.Encode.(forHtml|forHtmlContent|forHtmlAttribute|forHtmlUnquotedAttribute|forCssString|forCssUrl|forUri|forUriComponent|forXml|forXmlContent|forXmlAttribute|forXmlComment|forCDATA|forJava|forJavaScript|forJavaScriptAttribute|forJavaScriptBlock|forJavaScriptSource).*"

val encodeSantizers = "java.net.URLEncoder.(encode).*"

val decodeSantizers = "java.net.URLDecoder.(decode).*"

val stringUtilsSanitizers = "org.apache.commons.lang.StringEscapeUtils.(escapeJava|escapeJavaScript|unescapeJava|escapeHtml|unescapeHtml|escapeXml|escapeSql|unescapeCsv).*"

// Sinks
// -----

val commandInjectionSinks = "java.lang.Runtime.(exec).*|javax.xml.xpath.XPath.(compile).*|java.lang.Thread.(sleep).*|java.lang.System.(load|loadLibrary).*|java.lang.System.(load|loadLibrary).*|org.apache.xmlrpc.XmlRpcClient.(XmlRpcClient|execute|executeAsync).*"

val cookiePoisoningSinks = "javax.servlet.http.Cookie.(Cookie|setComment|setDomain|setPath|setValue).*"

val xssSinks = "java.io.PrintWriter.(print|println|write).*|javax.servlet.ServletOutputStream.(print|println).*|javax.servlet.jsp.JspWriter.(print|println).*|javax.servlet.ServletRequest.(setAttribute|setCharacterEncoding).*|javax.servlet.http.HttpServletResponse.(sendError|setDateHeader|addDateHeader|setHeader|addHeader|setIntHeader|addIntHeader).*|javax.servlet.ServletResponse.(setCharacterEncoding|setContentType).*|javax.servlet.http.HttpSession.(setAttribute|putValue).*"

val httpRespSplitSinks = "javax.servlet.http.HttpServletResponse.(sendRedirect|getRequestDispatcher).*"

val ldapInjectionSinks = "javax.naming.directory.InitialDirContext.(InitialDirContext|search).*|javax.naming.directory.SearchControls.(setReturningAttributes|connect|search).*"

val logForgingSinks = "java.io.PrintStream.(print|println).*|java.util.logging.Logger.(config|fine|finer|finest|info|warning|severe|entering|log).*|org.apache.commons.logging.Log.(debug|error|fatal|info|trace|warn).*|java.io.BufferedWriter.(write).*|javax.servlet.ServletContext.(log).*|javax.servlet.GenericServlet.(log).*"

val pathTraversalSinks = "java.io.(File|RandomAccessFile|FileReader|FileInputStream|FileWriter|FileOutputStream).*|java.lang.Class.(getResource|getResourceAsStream).*|javax.mail.internet.InternetAddress.(InternetAddress|parse).*"

val reflectionSinks = "java.lang.Class.(forName|getField|getMethod|getDeclaredField|getDeclaredMethod).*"

val misConfigSink = "java.sql.DriverManager.(getConnection).*"

val sqlInjectionSink = "java.sql.(Prepared)?Statement.(addBatch|execute|executeQuery|executeUpdate).*|java.sql.Connection.(prepareStatement|prepareCall|createStatement|executeQuery).*|javax.persistence.EntityManager.(createNativeQuery|createQuery).*|(org|net.sf).hibernate.Session.(createSQLQuery|createQuery|find|delete|save|saveOrUpdate|update|load).*"

val xpathInjectionSink =  "javax.xml.xpath.XPath.(compile|evaluate).*|javax.xml.xpath.XPathExpression.(evaluate).*|org.apache.xpath.XPath.(XPath).*|org.apache.commons.jxpath.JXPath.(getValue).*|org.xmldb.api.modules.XPathQueryService.(query).*|org.xmldb.api.modules.XMLResource.(setContent).*"

val compilerSink = "javax.tools.JavaCompiler.(getTask).*"

val fileSink = "java.io.File.(delete).*"

val forwardSink = ".*RequestDispatcher.*"

val classLoaderSink = "java.lang.ClassLoader.(defineClass).*"

val encodeSink = ".*java.util.Base64.*(encodeToString).*"

val decodeSink = ".*java.util.Base64.*(decode).*"