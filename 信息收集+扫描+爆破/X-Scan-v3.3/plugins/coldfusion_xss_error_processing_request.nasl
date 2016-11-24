#
# (C) Tenable Network Security
#

include("compat.inc");

if (description)
{
  script_id(24278);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2007-0817");
  script_bugtraq_id(22401);
  script_xref(name:"OSVDB", value:"32120");

  script_name(english:"ColdFusion Web Server User-Agent HTTP Header Error Message XSS");
  script_summary(english:"Checks for an XSS flaw in ColdFusion");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a cross-site scripting attack." );
 script_set_attribute(attribute:"description", value:
"The remote web server fails to sanitize user-supplied input to the
User-Agent header before using it to generate dynamic content in an
error page.  An unauthenticated remote attacker may be able to
leverage this issue to inject arbitrary HTML or script code into a
user's browser to be executed within the security context of the
affected site." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/459178/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb07-04.html" );
 script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch as described in the vendor advisory above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default: 80);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# Make sure it's ColdFusion.
res = http_get_cache(item:"/CFIDE/administrator/index.cfm", port:port);
if (res == NULL) exit(0);
if ("ColdFusion Administrator Login" >!< res) exit(0);


# Send a request to exploit the flaw.
xss = raw_string("<script>alert(", SCRIPT_NAME, ")</script>");
url = string("/CFIDE/administrator/nessus-", unixtime(), ".cfm");
r = http_send_recv3(method:"GET", item:url, port:port, 
  add_headers: make_array("User-Agent", xss));
if (isnull(r)) exit(0);
res = r[2];

# There's a problem if our exploit appears as the user agent.
browser = strstr(res, ">Browser&nbsp;&nbsp;</");
if (browser)
{
  browser = browser - strstr(browser, "</tr>");
  browser = strstr(browser, "<td>");
  browser = browser - strstr(browser, "</td>");
  # nb: browser includes some extra markup.
  if (string(">", xss) >< browser)
  {
   security_warning(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
