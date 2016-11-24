#
# This script was written by Georges Dagousset <georges.dagousset@alert4web.com>
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(10783);
 script_version ("$Revision: 1.13 $");

 script_cve_id("CVE-2000-0707");
 script_bugtraq_id(1557);
 script_xref(name:"OSVDB", value:"653");

 script_name(english:"PCCS-Mysql User/Password Exposure");
 
 script_set_attribute(attribute:"synopsis", value:
"Sensitive data may be read on the remote host." );
 script_set_attribute(attribute:"description", value:
"It is possible to read the include file of PCCS-Mysql, 
dbconnect.inc on the remote server.

This include file contains information such as the
username and password used to connect to the database." );
 script_set_attribute(attribute:"solution", value:
"Versions 1.2.5 and later are not vulnerable to this issue.
A workaround is to restrict access to the .inc file." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );


script_end_attributes();


 summary["english"] = "Checks for dbconnect.inc";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001-2009 Alert4Web.com");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);
res = is_cgi_installed_ka(port:port, item:"/pccsmysqladm/incs/dbconnect.inc");
if( res )security_hole(port);
