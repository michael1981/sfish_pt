#
# (C) Tenable Network Security
#

include("compat.inc");

if (description) {
  script_id(20171);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-3344");
  script_bugtraq_id(15337);
  script_xref(name:"OSVDB", value:"24117");

  script_name(english:"Horde Admin Account Default Password");
  script_summary(english:"Checks for default admin password vulnerability in Horde");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that uses a default
administrative password." );
 script_set_attribute(attribute:"description", value:
"The remote installation of horde uses an administrative account with
no password.  An attacker can leverage this issue to gain full control
over the affected application and to run arbitrary shell, PHP, and SQL
commands using the supplied admin utilities. 

Note that while the advisory is from Debian, the flaw is not specific
to that distribution - any installation of Horde that has not been 
completely configured is vulnerable." );
 script_set_attribute(attribute:"see_also", value:"http://www.debian.org/security/2005/dsa-884" );
 script_set_attribute(attribute:"see_also", value:"http://www.horde.org/horde/docs/?f=INSTALL.html#configuring-horde" );
 script_set_attribute(attribute:"solution", value:
"Either remove Horde or complete its configuration by configuring
an authentication backend." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("horde_detect.nasl");
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
install = get_kb_item(string("www/", port, "/horde"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to access the login script.
  r = http_send_recv3(method:"GET", item:string(dir, "/login.php"), port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if we get in. [If it were configured, we'd
  # get redirected back to login.php.]
  if ('<frame name="horde_' >< res) security_hole(port);
}
