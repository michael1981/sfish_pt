#
# This script was written by Josh Zlatin-Amishav <josh at ramat doti cc>
#
# This script is released under the GNU GPLv2



include("compat.inc");

if(description)
{
 script_id(19603);
 script_version ("$Revision: 1.14 $");

 script_cve_id(
  "CVE-2005-2674", 
  "CVE-2005-2675", 
  "CVE-2005-2788", 
  "CVE-2005-2884", 
  "CVE-2005-4821"
 );
 script_bugtraq_id(14618, 14619, 14685, 14746, 14820);
 script_xref(name:"OSVDB", value:"19292");
 script_xref(name:"OSVDB", value:"19293");
 script_xref(name:"OSVDB", value:"19294");
 script_xref(name:"OSVDB", value:"19295");
 script_xref(name:"OSVDB", value:"19296");
 script_xref(name:"OSVDB", value:"19297");
 script_xref(name:"OSVDB", value:"19299");
 script_xref(name:"OSVDB", value:"19300");
 script_xref(name:"OSVDB", value:"19301");
 script_xref(name:"OSVDB", value:"19504");
 script_xref(name:"OSVDB", value:"19505");

 name["english"] = "Land Down Under <= 801 Multiple Vulnerabilities";
 script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains several PHP scripts that permit SQL
injection and cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The remote version of Land Down Under is prone to several SQL
injection and cross-site scripting attacks due to its failure to
sanitize user-supplied input to several parameters used by the
'auth.php', 'events.php', 'index.php', 'list.php', and 'plug.php'
scripts.  A malicious user can exploit exploit these flaws to
manipulate SQL queries, steal authentication cookies, and the like." );
 script_set_attribute(attribute:"see_also", value:"http://www.packetstormsecurity.org/0509-advisories/LDU801.txt" );
 script_set_attribute(attribute:"see_also", value:"http://securityfocus.com/archive/1/409511" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2005-09/0381.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.g-0.org/code/ldu-adv.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


 summary["english"] = "Checks for SQL injection in LDU's list.php";
 script_summary(english:summary["english"]);

 script_category(ACT_ATTACK);

 script_family(english:"CGI abuses");
 script_copyright(english:"Copyright (C) 2005-2009 Josh Zlatin-Amishav");
 script_dependencie("ldu_detection.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/ldu"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 dir = matches[2];

 req = http_get(
   item:string(
     dir, "/list.php?",
     "c='&s=title&w=asc&o=", 
     SCRIPT_NAME, 
     "&p=1"
   ), 
   port:port
 );
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

 if 
 ( 
   "MySQL error" >< res && 
   egrep(string:res, pattern:string("syntax to use near '(asc&o=|0.+page_", SCRIPT_NAME, ")"))
 )
 {
        security_hole(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
        exit(0);
 }
}
