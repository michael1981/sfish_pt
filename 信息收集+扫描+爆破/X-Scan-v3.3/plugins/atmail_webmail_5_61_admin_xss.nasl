#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(38650);
  script_version("$Revision: 1.2 $");

  script_bugtraq_id(34762);
  script_xref(name:"OSVDB", value:"54126");
  script_xref(name:"Secunia", value:"34403");

  script_name(english:"Atmail WebMail < 5.61 webadmin/admin.php Multiple Parameter XSS");
  script_summary(english:"Checks the version number");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote host is running a web application with multiple cross-site\n",
      "scripting vulnerabilities."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The version of Atmail WebMail running on the remote host is\n",
      "vulnerable to multiple cross-site scripting issues.\n",
      "'webadmin/admin.php' fails to sanitize input to the 'func' parameter,\n",
      "and to the 'type' parameter (when 'func' is set to 'stats'). This is\n",
      "known to affect version 5.61 and may affect previous versions as\n",
      "well.\n\n",
      "A remote attacker could exploit this by tricking a user into\n",
      "requesting a web page with arbitrary script code injected. This could\n",
      "lead to consequences such as stolen authentication credentials."
    )
  );
  script_set_attribute(
    attribute:"solution",
    value:"There is no known solution at this time."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("atmail_webmail_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


install = get_kb_item(string("www/", port, "/atmail_webmail"));
if (isnull(install)) exit(0);

matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (isnull(matches)) exit(0);

dir = matches[2];

# Strip out only the version number (ver could look like "demo x.yz")
ver = matches[1];
matches = eregmatch(string:ver, pattern:" ?([0-9]+)\.([0-9])([0-9])?$");
if (isnull(matches)) exit(0);

major = int(matches[1]);
minor = int(matches[2]) * 10 + int(matches[3]);

if (
  major < 5 ||
  major == 5 && minor <= 61
)
{
  set_kb_item(name: 'www/' + port + '/XSS', value: TRUE);

  if (report_verbosity > 0)
  {
    xss = string("<script>alert('", SCRIPT_NAME, "')</script>");
    url = string(dir, "/webadmin/admin.php?func=", xss);

    report = string(
      "\n",
      "Nessus was only able to detect this issue by looking at the\n",
      "application's version number. Please confirm this issue exists by\n",
      "attempting a non-persisent XSS attack using the following URL :\n\n",
      "  ", build_url(port:port, qs:url), "\n\n",
      "Note that this URL requires authentication.\n"
    );

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
