#
# This script was written by Frank Berger <dev.null@fm-berger.de>
# <http://www.fm-berger.de>
#
# This vulnerability was found by 
# Rafel Ivgi, The-Insider <theinsider@012.net.il>
#
# License: GPL v 2.0  http://www.gnu.org/copyleft/gpl.html
#
#


include("compat.inc");

if(description)
{
 script_id(12112);
 script_version("$Revision: 1.13 $");
 name["english"] = "Oracle 9iAS iSQLplus XSS";
 name["francais"] = "Oracle 9iAS iSQLplus XSS";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The login-page of Oracle9i iSQLplus allows the injection of HTML and
JavaScript code via the username and password parameters." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the Oracle9i 'isqlplus' CGI
that is vulnerable to a cross-site scripting attack. 

An attacker may exploit this flaw to steal the cookies of legitimate
users on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.securitytracker.com/alerts/2004/Jan/1008838.html" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
 script_set_attribute(attribute:"solution", value: "No solution is known");
 script_end_attributes();

 
 summary["english"] = "Test for the possibility of an Cross-Site-Scripting XSS Attack in Oracle9i iSQLplus";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Frank Berger");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("find_service1.nasl", "http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/OracleApache");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if(get_port_state(port))
{ 
 req = http_get(item:"/isqlplus?action=logon&username=foo%22<script>foo</script>&password=test", port:port);	      
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if ( res == NULL ) exit(0);
 if( '<script>foo</script>' >< res )	
 {
 	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
 }
}
