#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11915);
 script_cve_id("CVE-2003-0542");
 script_xref(name:"OSVDB", value:"2733");
 script_xref(name:"OSVDB", value:"7611");
 script_xref(name:"Secunia", value:"10096");
 script_xref(name:"Secunia", value:"10845");
 script_xref(name:"Secunia", value:"17311");

 script_bugtraq_id(8911);
 script_version("$Revision: 1.14 $");
 
 script_name(english:"Apache < 1.3.29 Multiple Modules Local Overflow");
 script_summary(english:"Checks for version of Apache");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple local buffer overflow
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running a version of the Apache web
server which is older than 1.3.29. Such versions are reportedly
affected by local buffer overflow vulnerabilities in the mod_alias and
mod_rewrite modules. An attacker could exploit these vulnerabilities
to execute arbitrary code in the context of the affected application.

*** Note that Nessus solely relied on the version number
*** of the remote server to issue this warning. This might
*** be a false positive" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/342674/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Apache web server version 1.3.29 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 if ( ! defined_func("bn_random") )
	script_dependencie("http_version.nasl");
 else
 	script_dependencie("http_version.nasl", "macosx_version.nasl");
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

banner = get_http_banner(port: port);
if(!banner)exit(0);
banner = get_backport_banner(banner:banner);
 
serv = strstr(banner, "Server:");
if(!serv)exit(0);

if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/(1\.([0-2]\.[0-9]|3\.([0-9][^0-9]|[0-1][0-9]|2[0-8])))", string:serv))
 {
   security_hole(port);
 } 
