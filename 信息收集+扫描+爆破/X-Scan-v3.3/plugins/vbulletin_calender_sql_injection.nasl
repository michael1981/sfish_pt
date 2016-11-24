#
# (C) Tenable Network Security, Inc.
#

# Ref:
# From:   a1476854@hotmail.com
# Subject: vBulletin Forum 2.3.xx calendar.php SQL Injection
# Date: January 5, 2004 9:32:15 PM CET
# To:   bugtraq@securityfocus.com
#
#


include("compat.inc");

if(description)
{
  script_id(11981);
  script_version("$Revision: 1.12 $");
  script_cve_id("CVE-2004-0036");
  script_bugtraq_id(9360);
  script_xref(name:"OSVDB", value:"3344");

  script_name(english:"vBulletin calendar.php eventid Variable SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that suffers from a SQL
injection flaw." );
 script_set_attribute(attribute:"description", value:
"A vulnerability has been discovered in the 'calendar.php' script that
allows unauthorized users to inject SQL commands through the 'eventid'
parameter.  An attacker may use this flaw to gain the control of the
remote database." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-01/0027.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.vbulletin.com/forum/showthread.php?postid=588825" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to vBulletin 2.3.4 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
  script_summary(english:"Detect vBulletin Calendar SQL Injection");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencies("vbulletin_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port))exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/vBulletin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 path = matches[2];
 r = http_send_recv3(method:"GET",item:string(path, "/calendar.php?s=&action=edit&eventid=1'"), port:port);
 if (isnull(r)) exit(0);
 res = r[2];

 if ( "SELECT allowsmilies,public,userid,eventdate,event,subject FROM calendar_events WHERE eventid = 1'" >< res )
 {
   security_hole(port);
   set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
 }
}
