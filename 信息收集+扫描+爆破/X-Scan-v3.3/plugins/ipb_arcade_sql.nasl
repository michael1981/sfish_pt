#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
  script_id(15775);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2004-1536");
  script_bugtraq_id(11719);
  script_xref(name:"OSVDB", value:"12003");

  script_name(english:"Invision Power Board ibProArcade Module index.php cat Parameter SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a SQL
injection vulnerability." );
 script_set_attribute(attribute:"description", value:
"The installation of Invision Power Board on the remote host includes
an optional module, named 'Arcade', that allows unauthorized users to
inject SQL commands into the remote SQL database through the 'cat'
parameter.  An attacker may use this flaw to gain control of the
remote database and possibly to overwrite files on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-11/0264.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Detect Invision Power Board Arcade SQL Injection";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
 
  script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencies("invision_power_board_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/invision_power_board"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 path = matches[2];

 req = http_get(item:string(path, "/index.php?act=Arcade&cat=1'"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

 if ("mySQL query error: SELECT g.*, c.password FROM ibf_games_list AS" >< res)
 {
  security_hole(port);
   set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
 }
}
