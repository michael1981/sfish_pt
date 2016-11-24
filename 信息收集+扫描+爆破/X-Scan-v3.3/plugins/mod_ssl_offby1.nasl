#
# This script was written by Thomas Reinke <reinke@e-softinc.com>,
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, OSVDB ref, output formatting (9/18/09)


include("compat.inc");

if(description)
{
 script_id(11039);
 script_version("$Revision: 1.20 $");
 script_cve_id("CVE-2002-0653");
 script_bugtraq_id(5084);
 script_xref(name:"OSVDB", value:"842");
 script_xref(name:"SuSE", value:"SUSE-SA:2002:028");
 
 script_name(english:"Apache mod_ssl ssl_compat_directive Function Overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is using a module that is affected by a remote
code execution vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is using a version of mod_ssl which is older 
than 2.8.10.

This version is vulnerable to an off by one buffer overflow which may
allow a user with write access to .htaccess files to execute arbitrary
code on the system with permissions of the web server.

*** Note that several Linux distributions (such as RedHat)
*** patched the old version of this module. Therefore, this
*** might be a false positive. Please check with your vendor
*** to determine if you really are vulnerable to this flaw" );
 script_set_attribute(attribute:"see_also", value:"http://marc.theaimsgroup.com/?l=vuln-dev&m=102477330617604&w=2" );
 script_set_attribute(attribute:"see_also", value:"http://marc.theaimsgroup.com/?l=bugtraq&m=102513970919836&w=2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to mod_ssl version 2.8.10 or newer" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Checks for version of mod_ssl");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Thomas Reinke");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("backport.inc");
include("global_settings.inc");

port = get_http_port(default:80);

if ( report_paranoia < 2 ) exit(0);

if(get_port_state(port))
{
 banner = get_backport_banner(banner:get_http_banner(port:port));
 if(!banner || backported )exit(0);
 
 serv = strstr(banner, "Server");
 if("Apache/" >!< serv ) exit(0);
 if("Apache/2" >< serv) exit(0);
 if("Apache-AdvancedExtranetServer/2" >< serv)exit(0);

 if(ereg(pattern:".*mod_ssl/(1.*|2\.([0-7]\..*|8\.[0-9][^0-9])).*", string:serv))
 {
   security_warning(port);
 }
}
