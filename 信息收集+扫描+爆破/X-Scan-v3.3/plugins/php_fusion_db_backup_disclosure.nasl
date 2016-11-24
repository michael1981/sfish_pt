#
# (C) Tenable Network Security
#

include("compat.inc");

if(description)
{
 script_id(14356);
 script_cve_id("CVE-2004-1724");
 script_bugtraq_id(10974);
 script_xref(name:"OSVDB", value:"9032");
 script_version("$Revision: 1.10 $");
 
 name["english"] = "PHP-Fusion Database Backup Disclosure";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"A vulnerability exists in the remote version of PHP-Fusion that may
allow an attacker to obtain a dump of the remote database.  PHP-Fusion
has the ability to create database backups and store them on the web
server, in the directory '/fusion_admin/db_backups/'.  Since there is
no access control on that directory, an attacker may guess the name of
a backup database and download it." );
 script_set_attribute(attribute:"see_also", value:"http://echo.or.id/adv/adv04-y3dips-2004.txt" );
 script_set_attribute(attribute:"solution", value:
"Use a .htaccess file or the equivalent to control access to files in
the backup directory." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 summary["english"] = "Checks the version of the remote PHP-Fusion";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencies("http_version.nasl", "php_fusion_detect.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port))exit(0);
if (get_kb_item("www/no404/"+port)) exit(0);

kb = get_kb_item("www/" + port + "/php-fusion");
if ( ! kb ) exit(0);

items = eregmatch(string:kb, pattern:"(.*) under (.*)");
ver   = items[1];
loc   = items[2];

if ( ver =~ "^([0-3][.,]|4[.,]00)" )
{
  w = http_send_recv3(method:"GET",item:string(loc, "/fusion_admin/db_backups/"), port:port);
  if (isnull(w)) exit(0);
  r = w[2];
  if ( egrep(pattern:"^HTTP/.* 200 .*", string:r) )
	{ 
  	security_warning(port);
	}
  exit(0);
}
