#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42801);
  script_version("$Revision: 1.2 $");

  script_bugtraq_id(37005, 37014);
  script_xref(name:"OSVDB", value:"59958");
  script_xref(name:"OSVDB", value:"59959");
  script_xref(name:"Secunia", value:"37332");

  script_name(english:"WordPress < 2.8.6 Multiple Vulnerabilities");
  script_summary(english:"Checks the version number");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP application with multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version number, the installation of WordPress is
affected by multiple vulnerabilities :

  - It is possible for an attacker with valid credentials to
    upload arbitrary files, potentially leading to arbitrary
    code execution.

  - A cross-site scripting vulnerability exists in
    'Press-This'."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c5090570"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/507819/30/0/threaded"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to WordPress 2.8.6 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P"
  );
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/11/11"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/11/11"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/11/13"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http.inc");
include("misc_func.inc");
include("global_settings.inc");
include("webapp_func.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0, "The web server on port "+port+" does not support PHP scripts.");

install = get_install_from_kb(appname:'wordpress', port:port);
if (isnull(install)) exit(1, "WordPress wasn't detected on port "+port+".");

if (report_paranoia<2) exit(1, "This plugin only runs if 'Report paranoia' is set to 'Paranoid'.");

dir = install['dir'];
version = install['ver'];

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Versions < 2.8.6 are affected.
if (
  ver[0] < 2 ||
  (
    ver[0] == 2 &&
    (
      ver[1] < 8 ||
      (
        ver[1] == 8 &&
        (
          max_index(ver) == 2 || 
          ver[2] < 6
        )
      )
    )
  )
)
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "Nessus found the following vulnerable WordPress install :\n",
      "\n",
      "  URL               :", build_url(port:port, qs:dir+"/"), "\n",
      "  Installed version : ", version, "\n",
      "  Fixed version     : 2.8.6"
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);

  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  exit(0);
}
exit(0, "Version "+version+" of WordPress is installed at "+build_url(port:port, qs:dir+"/")+" and hence not affected.");
