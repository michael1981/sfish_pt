#
# (C) Tenable Network Security
# 


include("compat.inc");

if(description)
{
 script_id(15986);
 script_cve_id("CVE-2004-1406");
 script_bugtraq_id(11982);
 script_xref(name:"OSVDB", value:"12476");
 script_xref(name:"Secunia", value:"13513");
 script_version ("$Revision: 1.8 $");
 
 script_name(english:"Ikonboard ikonboard.cgi Multiple Parameter SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a Perl application that is affected
by multiple SQL injection vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote server is running IkonBoard, a Web Bulletin Board System
written in Perl.

The remote version of this software fails to sanitize user supplied
input to multiple variables in the 'ikonboard.cgi' script.  An
attacker can exploit this flaw to launch SQL injection attacks." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-12/0192.html" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );


script_end_attributes();

 
 summary["english"] = "Checks for Ikonboard.cgi";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("http.inc");
include("misc_func.inc");
include("global_settings.inc");


port = get_http_port(default:80);


if(!get_port_state(port))exit(0);


foreach d (cgi_dirs())
{
 res = http_send_recv3(method:"GET", item:d+"/ikonboard.cgi?act=ST&f=1&t=1&hl=nessus&st='", port:port);
 if (isnull(res)) exit(1, "The remote web server did not respond.");

 if ( "SELECT * FROM ib_forum_posts WHERE TOPIC_ID = '1' AND QUEUED <> '1' ORDER BY POST_DATE ASC LIMIT" >< res[2])
 {
   security_hole(port:port);
   set_kb_item(name:'www/'+port+'/SQLInjection',value:TRUE);
   exit(0);
 }
}
