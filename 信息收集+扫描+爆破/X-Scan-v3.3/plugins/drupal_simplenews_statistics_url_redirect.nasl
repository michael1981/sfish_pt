#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42254);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-3784");
  script_bugtraq_id(36790);
  script_xref(name:"OSVDB", value:"59150");
  script_xref(name:"Secunia", value:"37128");

  script_name(english:"Drupal SA-CONTRIB-2009-080: Simplenews Statistics Open Redirect");
  script_summary(english:"Tries to exploit the redirect");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a PHP application that has an open
redirect."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installation of Drupal on the remote host includes the third-party
Simplenews Statistics module, which provides newsletter statistics
such as open and click-through rates. 

The version of Simplenews Statistics installed contains an open
redirect, which can be used in a phishing attack to trick users into
visiting malicious sites."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://drupal.org/node/611002"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Simplenews Statistics version 6.x-2.0 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/10/21"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/10/21"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/10/24"
  );
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("drupal_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0, "The web server on port "+port+" does not support PHP scripts.");


# Test an install
install = get_kb_item(string("www/", port, "/drupal"));
if (isnull(install)) exit(1, "The 'www/"+port+"/drupal' KB item is missing.");
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (isnull(matches)) exit(1, "The 'www/"+port+"/drupal' KB item ("+install+") is invalid.");
dir = matches[2];


# Try to exploit the issue.
redirect = "http://www.nessus.org/";
url = string(
  dir, "/simplenews/statistics/click?",
  "url=", redirect
);

res = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(res)) exit(1, "The web server failed to respond.");

hdrs = parse_http_headers(status_line:res[0], headers:res[1]);
if (isnull(hdrs['$code'])) code = 0;
else code = hdrs['$code'];

if (isnull(hdrs['location'])) location = "";
else location = hdrs['location'];

# There's a problem if ...
if (
  # we're redirected and ...
  code == 302 &&
  # it's to the location we specified
  redirect == location
)
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "Nessus was able to verify the issue using the following URL :\n",
      "\n",
      " ", build_url(port:port, qs:url), "\n"
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);

  exit(0);
}
else exit(0, "The installed version of Simplenews Statistics is not affected.");
