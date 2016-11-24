#
# (C) Tenable Network Security
#



include("compat.inc");

if (description)
{
  script_id(21144);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2006-0871", "CVE-2006-1794");
  script_bugtraq_id(16775);
  script_xref(name:"OSVDB", value:"23402");
  script_xref(name:"OSVDB", value:"23503");
  script_xref(name:"OSVDB", value:"23505");

  script_name(english:"Mambo Open Source Multiple Vulnerabilities");
  script_summary(english:"Tries to change mos_user_template cookie in Mambo Open Source");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
several issues." );
 script_set_attribute(attribute:"description", value:
"The remote installation of Mambo Open Source fails to sanitize input
to the 'mos_user_template' cookie before using it to include PHP code
from a local file.  An unauthenticated attacker may be able to exploit
this issue to view arbitrary files or to execute arbitrary PHP code on
the affected host. 

In addition, the application suffers from a similar lack of sanitation
of input to the 'username' parameter in the 'includes/mambo.php'
script, the 'task' parameter in 'index2.php', and the 'filter'
parameter in 'components/com_content/content.php' before using it in
SQL statements.  Provided PHP's 'magic_quotes_gpc' setting is
disabled, an attacker can leverage these issues to manipulate database
queries and, for example, log in as any user, including an admin." );
 script_set_attribute(attribute:"see_also", value:"http://www.gulftech.org/?node=research&article_id=00104-02242006" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2006-02/0463.html" );
 script_set_attribute(attribute:"solution", value:
"Apply the appropriate security patch listed in the vendor advisory
above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("mambo_detect.nasl");
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
install = get_kb_item(string("www/", port, "/mambo_mos"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];
  set_http_cookie(name: "mos_user_template", value: "./../administrator/");
  r = http_send_recv3(method: "GET", item:string(dir, "/index.php"), port:port);
  if (isnull(r)) exit(0);

  # There's a problem if we were able to set the cookie.
  if (get_http_cookie(name: "mos_user_template") == ".%2F..%2Fadministrator%2F")
  {
    security_warning(port);
    exit(0);
  }
}
