#
# This script was written by Alexis de Bernis <alexisb@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(10034);
 script_bugtraq_id(2059);
 script_version ("$Revision: 1.23 $");
 script_cve_id("CVE-1999-0710");
 script_xref(name:"OSVDB", value:"28");
 script_name(english:"Squid cachemgr.cgi Proxied Port Scanning");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI application that has no access 
restrictions." );
 script_set_attribute(attribute:"description", value:
"RedHat Linux 6.0 installs by default a squid cache manager cgi script with
no restricted access permissions. This script could be used to perform a
port scan from the cgi-host machine." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/1999-q3/0194.html" );
 script_set_attribute(attribute:"solution", value:
"If you are not using the box as a Squid www proxy/cache server then
uninstall the package by executing:
/etc/rc.d/init.d/squid stop ; rpm -e squid

If you want to continue using the Squid proxy server software, make the
following actions to tighten security access to the manager interface:
mkdir /home/httpd/protected-cgi-bin
mv /home/httpd/cgi-bin/cachemgr.cgi /home/httpd/protected-cgi-bin/

And add the following directives to /etc/httpd/conf/access.conf and
srm.conf:

--- start access.conf segment ---
# Protected cgi-bin directory for programs that
# should not have public access
order deny,allow
deny from all
allow from localhost
#allow from .your_domain.com
AllowOverride None
Options ExecCGI
--- end access.conf segment ---

--- start srm.conf segment ---
ScriptAlias /protected-cgi-bin/ /home/httpd/protected-cgi-bin/
--- end srm.conf segment ---" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 summary["english"] = "Checks whether the cachemgr.cgi is installed and accessible."; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999-2009 A. de Bernis");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl",  "no404.nasl");
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

cgi = "cachemgr.cgi";
res = is_cgi_installed_ka(item:cgi, port:port);
if(res)security_hole(port);
