#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(18300);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2005-1608");
  script_bugtraq_id(13539);
  script_xref(name:"OSVDB", value:"16346");

  script_name(english:"PostNuke AutoTheme Module Multiple Unspecified Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that suffers from multiple
issues." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of AutoTheme for PostNuke on the
remote host suffers from multiple, unspecified vulnerabilities
affecting the 'Blocks' module.  Reportedly, some of these issues may
allow a remote attacker to gain unauthorized access to the remote
host. 

Note that the recommended security fix does not alter AutoTheme's
banner so if you know for certain that it's been applied, treat this
as a false positive." );
 script_set_attribute(attribute:"see_also", value:"http://community.postnuke.com/Article2687.htm" );
 script_set_attribute(attribute:"solution", value:
"Apply the Blocks module Security Fix referenced in the URL or upgrade
to a newer version of the software when available." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for multiple unspecified vulnerabilities in AutoTheme PostNuke module";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("postnuke_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/postnuke"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  # Check for AutoTheme's banner.
  pat = "^\*+ (AutoTheme|AT-Lite) ([^*]+) \*+$";
  matches = egrep(string:res, pattern:pat, icase:TRUE);
  if (matches) {
    foreach match (split(matches)) {
      match = chomp(match);
      banner = eregmatch(pattern:pat, string:match);
      # Extract the product and version number.
      if (!isnull(banner)) {
        prod = banner[1];
        ver = banner[2];

        # Check whether the software is vulnerable.
        if (
          (prod =~ "AutoTheme" && ver =~ "^(0\.|1\.([0-6][^0-9]|7\.0))") ||
          (prod =~ "AT-Lite" && ver =~ "^\.([0-7][^0-9]?|8$)")
        ) {
          security_hole(port);
          exit(0);
        }
      }
    }
  }
}
