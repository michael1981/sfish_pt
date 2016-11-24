#
# This script was written by Audun Larsen <larsen@xqus.com>
#
# Based on Apache < 1.3.27 written by Renaud Deraison <deraison@cvs.nessus.org>
#

# Changes by Tenable:
# - Revised plugin title, OSVDB ref (9/23/09)
# - Updated to use compat.inc (11/20/2009)



include("compat.inc");

if(description)
{
 script_id(12073);
 script_version("$Revision: 1.10 $");
 script_cve_id("CVE-2004-0292");
 script_bugtraq_id(9679);
 script_xref(name:"OSVDB", value:"3970");
 
 script_name(english:"Sami HTTP Server 1.0.4 GET Request Remote Overflow");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote web server." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote web server is running Sami HTTP
server is v1.0.4 or older.  An attacker may be capable of corrupting
data such as the return address, and thereby control the execution
flow of the program.  This may result in denial of service or
execution of arbitrary code." );
 script_set_attribute(attribute:"see_also", value:"http://www.karjasoft.com/old.php" );
 script_set_attribute(attribute:"solution", value:
"Use another web server since Sami HTTP is not maintained any more." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Checks for version of Sami HTTP server");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Audun Larsen");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("backport.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
banner = get_http_banner(port: port);
if(!banner)exit(0);
banner = get_backport_banner(banner:banner);

if ( egrep(pattern:"Server:.*Sami HTTP Server v(0\.|1\.0\.[0-4][^0-9])", string:banner) ) 
 {
   security_hole(port);
 }
}
