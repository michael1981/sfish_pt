#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(20383);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2006-0125");
  script_bugtraq_id(16166);
  script_xref(name:"OSVDB", value:"22228");

  script_name(english:"AppServ appserv/main.php appserv_root Variable Remote File Inclusion");
  script_summary(english:"Checks for appserv_root parameter remote file include vulnerability in AppServ");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to a remote file inclusion
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running AppServ, a compilation of
Apache, PHP, MySQL, and phpMyAdmin for Windows and Linux. 

The version of AppServ installed on the remote host fails to sanitize
user-supplied input to the 'appserv_root' parameter of the
'appserv/main.php' script before using it in a PHP 'include' function. 
An unauthenticated attacker can exploit this flaw to run arbitrary
code, possibly taken from third-party hosts, subject to the privileges
of the web server user id.  Note that AppServ under Windows runs with
SYSTEM privileges, which means an attacker can gain complete control
of the affected host." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Try to exploit the flaw.
#
# nb: AppServ is always installed under "/appserv".
r = http_send_recv3(method:"GET", port:port,
  item:string("/appserv/main.php?appserv_root=", SCRIPT_NAME) );
if (isnull(r)) exit(0);
res = r[2];

# There's a problem if we get an error saying "failed to open stream".
if (egrep(pattern:string(SCRIPT_NAME, "/lang-.+\\.php\\): failed to open stream"), string:res)) {
  security_warning(port);
  exit(0);
}
