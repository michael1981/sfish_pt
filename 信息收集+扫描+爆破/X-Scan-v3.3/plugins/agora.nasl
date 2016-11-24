#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(10836);
 script_bugtraq_id(3702);
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-2001-1199");
 script_xref(name:"OSVDB", value:"698");
 
 script_name(english:"AgoraCart agora.cgi cart_id Parameter XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI which is vulnerable to a cross-site
scripting issue." );
 script_set_attribute(attribute:"description", value:
"Agora is a CGI based e-commerce package. Due to poor input validation, 
Agora allows an attacker to execute cross-site scripting attacks." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Agora 4.0e or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 
 summary["english"] = "Tests for Agora CGI Cross Site Scripting";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Matt Moore");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here
#include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (report_paranoia < 2) exit(0);
port = get_http_port(default:80);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

if(get_port_state(port))
{ 
 req = http_get(item:"/store/agora.cgi?cart_id=<SCRIPT>alert(document.domain)</SCRIPT>&xm=on&product=HTML", port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if ( r == NULL ) exit(0);
 if("<SCRIPT>alert(document.domain)</SCRIPT>" >< r)	{
		security_warning(port);
		set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	}
}
