#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(38649);
  script_version("$Revision: 1.2 $");

  script_bugtraq_id(34529);
  script_xref(name:"OSVDB", value:"53682");
  script_xref(name:"Secunia", value:"34704");

  script_name(english:"Atmail WebMail < 5.6 Email Body Injection");
  script_summary(english:"Checks the version number");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote host is running a webmail application with a content\n",
      "injection vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The version of Atmail WebMail running on the remote host is\n",
      "vulnerable to an email body injection attack. HTML and script code\n",
      "are not properly sanitized before it is displayed in dynamically\n",
      "generated content. This vulnerability is known to affect versions\n",
      "5.6 and earlier.\n\n",
      "A remote attacker could exploit this by sending a specially crafted\n",
      "email to display arbitrary HTML and script code in a user's web\n",
      "browser."
    )
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Atmail WebMail version 5.61 or later."
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
  major == 5 && minor <= 60
)
{
  set_kb_item(name: 'www/' + port + '/XSS', value: TRUE);

  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "Nessus was only able to detect this issue by looking at the\n",
      "application's version number.\n"
    );

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
