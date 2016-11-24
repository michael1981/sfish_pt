#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(18124);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2005-1193", "CVE-2005-1290");
  script_bugtraq_id(13344, 13345, 13545);
  script_xref(name:"OSVDB", value:"15919");
  script_xref(name:"OSVDB", value:"16439");

  script_name(english:"phpBB <= 2.0.14 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of phpBB
that suffers from multiple flaws:

  - A BBCode Input Validation Vulnerability
    The application fails to properly filter for the BBCode
    URL in the 'includes/bbcode.php' script. With a specially-
    crafted URL, an attacker cause arbitrary script code to be 
    executed in a user's browser, possibly even to modify
    registry entries without the user's knowledge.

  - Cross-Site Scripting Vulnerabilities
    The application does not properly sanitize user-supplied input
    to the 'forumname' and 'forumdesc' parameters of the 
    'admin/admin_forums.php' script. By enticing an phpBB 
    administrator to visit a a specially-crafted link, an attacker
    can potentially steal the admin's session cookie or perform
    other attacks.

  - Improper Filtering of HTML Code
    The application does not completely filter user-supplied input
    to the 'u' parameter of the 'profile.php' script or the 
    'highlight' parameter of the 'viewtopic.php' script." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-04/0383.html" );
 script_set_attribute(attribute:"see_also", value:"http://castlecops.com/t123194-.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.phpbb.com/phpBB/viewtopic.php?f=14&t=288194" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpBB version 2.0.15 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in phpBB 2.0.14 and older";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencies("phpbb_detect.nasl");
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
install = get_kb_item(string("www/", port, "/phpBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  if (ver =~ "^([01]\..*|2\.0\.([0-9]|1[0-4])([^0-9]|$))")
  {
   security_warning(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}

