#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(18552);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2005-1250");
  script_bugtraq_id(14039);
  script_xref(name:"OSVDB", value:"17450");

  script_name(english:"Ipswitch WhatsUp Professional Login.asp Multiple Field SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP script that is vulnerable to a
SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Ipswitch WhatsUp Professional, a network
management and monitoring package. 

The web front-end for WhatsUp Professional on the remote host is prone
to a SQL injection attack because it fails to sanitize the 'sUserName'
and 'sPassword' parameters in the 'Login.asp' script.  An attacker may
be able to exploit this flaw to gain unauthenticated administrative
access to the affected application. 

Note that the web front-end is not installed as part of a default
configuration." );
 script_set_attribute(attribute:"see_also", value:"http://www.idefense.com/application/poi/display?id=268&type=vulnerabilities" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Ipswitch WhatsUp Pro 2005 SP1a or disable its web
front-end." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_summary(english:"Checks for SQL injection vulnerability in Ipswitch WhatsUp Professional's Login.asp");
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# If the banner indicates it's for Ipswitch...
banner = get_http_banner(port:port);
if (banner && "Server: Ipswitch" >< banner) {
  # Try to exploit the flaw.
  postdata = string(
    "sUsername=", SCRIPT_NAME, "'&",
    "sPassword=nessus&",
    "btnLogin=Log+In&",
    "bIsJavaScriptDisabled=true"
  );
  req = string(
    "POST /NmConsole/Login.asp HTTP/1.1\r\n",
    "Host: ", get_host_name(), "\r\n",
    "Content-Type: application/x-www-form-urlencoded\r\n",
    "Content-Length: ", strlen(postdata), "\r\n",
    "\r\n",
    postdata
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we see a syntax error.
  if (string("quotation mark before the character string '", SCRIPT_NAME, "''") >< res) {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
