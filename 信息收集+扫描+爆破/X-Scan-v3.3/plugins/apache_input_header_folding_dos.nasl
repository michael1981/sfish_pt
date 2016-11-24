#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
# ref: Georgi Guninski (June 2004)
#
# This script is released under the GNU GPLv2

# Changes by Tenable:
# - Standardized plugin title, changed family (4/2/2009)


include("compat.inc");

if(description)
{
 script_id(12293);
 script_bugtraq_id(10619, 12877);
 script_version("$Revision: 1.14 $");
 script_cve_id("CVE-2004-0493", "CVE-2004-0748");
 script_xref(name:"OSVDB", value:"7269");
 script_xref(name:"OSVDB", value:"9523");
  
 script_name(english:"Apache < 2.0.50 Multiple Remote DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to multiple denial of service attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running a version of Apache 2.x which is
older than 2.0.50. 

There is denial of service flaw in Apache 2.0.x that can be triggered
by sending a specially-crafted HTTP request, which results in the
consumption of an arbitrary amount of memory.  On 64-bit systems with
more than 4GB virtual memory, this may lead to heap based buffer
overflow. 

There is also a denial of service vulnerability in mod_ssl's
'ssl_io_filter_cleanup' function.  By sending a request to vulnerable
server over SSL and closing the connection before the server can send
a response, an attacker can cause a memory violation that crashes the
server." );
 script_set_attribute(attribute:"see_also", value:"http://www.guninski.com/httpd1.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Apache 2.0.50 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
 summary["english"] = "Checks for version of Apache";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_keys("www/apache");
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
banner = get_backport_banner(banner:get_http_banner(port: port));
if(!banner)exit(0);
 
if(egrep(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/2\.0\.(([0-9][^0-9])([0-3][0-9][^0-9])|(4[0-9][^0-9])).*", string:banner))
 {
   security_warning(port);
 }
}
