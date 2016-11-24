#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
  script_id(15778);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2004-1531");
  script_bugtraq_id(11703);
  script_xref(name:"OSVDB", value:"11929");

  script_name(english:"Invision Power Board sources/post.php qpid Parameter SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is vulnerable to
a SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"The version of Invision Power Board on the remote host suffers from a
flaw in 'sources/post.php' that allows injection of SQL commands into
the remote SQL database.  An attacker may use this flaw to gain
control of the remote database and possibly to overwrite files on the
remote host." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-11/0233.html" );
 script_set_attribute(attribute:"see_also", value:"http://forums.invisionpower.com/index.php?showtopic=154916" );
 script_set_attribute(attribute:"solution", value:
"Replace the 'sources/post.php' file with the one referenced in the
vendor advisory above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
  summary["english"] = "Detect Invision Power Board Post SQL Injection";
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

 req = http_get(item:string(path, "/index.php?act=Post&CODE=02&f=3&t=10&qpid=1'"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

 if ("mySQL query error: select p.*,t.forum_id FROM ibf_posts p LEFT JOIN ibf_topics t ON (t.tid=p.topic_id)" >< res)
 {
  security_hole(port);
   set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
 }
}
