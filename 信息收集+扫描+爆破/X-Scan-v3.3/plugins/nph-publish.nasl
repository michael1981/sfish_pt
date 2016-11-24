#
# This script was written by Mathieu Perrin <mathieu@tpfh.org>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin description, removed invalid CVE, added OSVDB (4/21/009)


include("compat.inc");

if(description)
{
 script_id(10164);
 script_version ("$Revision: 1.24 $");

 script_cve_id("CVE-1999-1177");
 script_xref(name:"OSVDB", value:"127");
 
 script_name(english:"Lincoln D. Stein nph-publish.cgi pathname Parameter Traversal Arbitrary File Write");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary commands maight be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"The 'nph-publish.cgi' is installed. This CGI has a well known security 
flaw that lets an attacker to execute arbitrary commands with the 
privileges of the HTTP daemon (usually root or nobody)." );
 script_set_attribute(attribute:"solution", value:
"Remove it from /cgi-bin." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();


 summary["english"] = "Checks for the presence of /cgi-bin/nph-publish.cgi";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Mathieu Perrin");
 script_family(english:"CGI abuses");
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
res = is_cgi_installed_ka(port:port, item:"nph-publish.cgi");
if( res )security_hole(port);
