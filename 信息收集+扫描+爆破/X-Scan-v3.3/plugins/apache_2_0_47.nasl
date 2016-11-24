#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11788);
 script_bugtraq_id(8134, 8135, 8137, 8138);
 script_cve_id("CVE-2003-0192", "CVE-2003-0253", "CVE-2003-0254");
 script_xref(name:"RHSA", value:"RHSA-2003:243-01");
 script_xref(name:"OSVDB", value:"2672");
 script_xref(name:"OSVDB", value:"12557");
 script_xref(name:"OSVDB", value:"12558");
 script_xref(name:"Secunia", value:"10008");
 script_xref(name:"Secunia", value:"9813");

 script_version("$Revision: 1.14 $");
 
 script_name(english:"Apache < 2.0.47 Multiple Vulnerabilities (DoS, Encryption)");
 script_summary(english:"Checks version of Apache");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running a version of Apache 2.x which is
older than 2.0.47. Such versions are reportedly affected by multiple
vulnerabilities :

  - An issue in may occur when the SSLCipherSuite directive
    is used to upgrade a cipher suite which could lead to a
    weaker cipher suite being used instead of the upgraded
    one. (CVE-2003-0192)

  - A denial of service vulnerability may exist in the FTP
    proxy component relating to the use of IPV6 addresses.
    (CVE-2003-0253)

  - An attacker may be able to craft a type-map file that
    could cause the server to enter an infinite loop.
    (CVE-2003-0254)" );
 script_set_attribute(attribute:"see_also", value:"http://www.apache.org/dist/httpd/CHANGES_2.0" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Apache web server version 2.0.47 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P" );

 script_end_attributes();
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl");
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

port = get_http_port(default:80);

banner = get_backport_banner(banner:get_http_banner(port: port));
if(!banner)exit(0);
 
serv = strstr(banner, "Server");
if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/2\.0\.([0-9][^0-9]|[0-3][0-9]|4[0-6])", string:serv))
 {
   security_warning(port);
 }
