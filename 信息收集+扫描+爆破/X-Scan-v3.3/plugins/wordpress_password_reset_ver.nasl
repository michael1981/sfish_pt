#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40578);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2009-2762");
  script_bugtraq_id(36014);
  script_xref(name:"OSVDB", value:"56971");
  script_xref(name:"Secunia", value:"36237");
  script_xref(name:"milw0rm", value:"9410");

  script_name(english:"WordPress < 2.8.4 wp-login.php key Parameter Remote Administrator Password Reset (uncredentialed check)");
  script_summary(english:"Version check");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server contains a PHP application with a security\n",
      "bypass vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "According to its version number, the version of WordPress running\n",
      "on the remote server has a flaw in the password reset mechanism.\n",
      "Validation of the secret user activation key can be bypassed by\n",
      "providing an array instead of a string.  This allows anyone to reset\n",
      "the password of the first user in the database, which is usually the\n",
      "administrator.  A remote attacker could use this to repeatedly reset\n",
      "the password, leading to a denial of service."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://archives.neohapsis.com/archives/fulldisclosure/2009-08/0114.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://core.trac.wordpress.org/changeset/11798"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://wordpress.org/development/2009/08/2-8-4-security-release/"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to WordPress 2.8.4 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/08/10"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/08/12"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/08/12"
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

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0, "Web server does not support PHP scripts.");

install = get_kb_item('www/' + port + '/wordpress');
if (isnull(install)) exit(1, "The 'www/"+port+"/wordpress' KB item is missing.");

match = eregmatch(string:install, pattern:'(.+) under /.*$', icase:TRUE);
if (isnull(match)) exit(1, "Unable to read install info from KB.");

version = match[1];
ver_fields = split(version, sep:'.', keep:FALSE);
major = int(ver_fields[0]);
minor = int(ver_fields[1]);
rev = int(ver_fields[2]);

# Versions < 2.8.4 are affected
if (
  major < 2 ||
  (major == 2 && minor < 8) ||
  (major == 2 && minor == 8 && rev < 4)
)
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "  Installed version  : ", version, "\n",
      "  Should be at least : 2.8.4\n"
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);

  exit(0);
}
else exit(0, "The remote WordPress install does not appear to be affected.");
