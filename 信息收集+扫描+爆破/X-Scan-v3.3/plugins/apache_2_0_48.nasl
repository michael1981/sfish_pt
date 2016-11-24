#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11853);
 script_bugtraq_id(8926);
 script_version("$Revision: 1.18 $");
 script_cve_id("CVE-2003-0789", "CVE-2003-0542");
 script_xref(name:"OSVDB", value:"2733");
 script_xref(name:"OSVDB", value:"7611");
 script_xref(name:"OSVDB", value:"15889");
 script_xref(name:"Secunia", value:"10096");
 script_xref(name:"Secunia", value:"10845");
 script_xref(name:"Secunia", value:"17311");

 script_name(english:"Apache < 2.0.48 Multiple Vulnerabilities (OF, Info Disc.)");
 script_summary(english:"Checks for version of Apache");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running a version of Apache 2.x which is
older than 2.0.48. Such versions are reportedly affected by multiple
vulnerabilities.

  - The mod_rewrite and mod_alias modules fail to handle
    regular expressions containing more than 9 captures
    resulting in a buffer overflow.

  - A vulnerability may occur in the mod_cgid module caused
    by the mishandling of CGI redirect paths. This could
    cause Apache to send the output of a CGI program to the
    wrong client." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/342674/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2004/Jan/msg00000.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Apache web server version 2.0.48 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 if ( ! defined_func("bn_random") )
	script_dependencie("http_version.nasl");
 else
 	script_dependencie("http_version.nasl", "redhat-RHSA-2004-015.nasl", "redhat-RHSA-2003-360.nasl");
 script_require_keys("www/apache");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("backport.inc");

if ( get_kb_item("CVE-2003-0542") ) exit(0);

port = get_http_port(default:80);

banner = get_backport_banner(banner:get_http_banner(port: port));
if(!banner)exit(0);
 
serv = strstr(banner, "Server");
if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/2\.0\.([0-9][^0-9]|[0-3][0-9]|4[0-7])", string:serv))
 {
   security_hole(port);
 }
