#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11408);
 script_bugtraq_id(6065);
 script_cve_id("CVE-2002-1156", "CVE-2003-0083");
 script_xref(name:"OSVDB", value:"9702");
 script_xref(name:"OSVDB", value:"9711");

 script_version("$Revision: 1.16 $");
 
 script_name(english:"Apache < 2.0.43 Multiple Vulnerabilities (Log Injection, Source Disc.)");
 script_summary(english:"Checks for version of Apache");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information discolsure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running a version of
Apache 2.x which is older than 2.0.43.

Such versions are reportedly affected by an infomration disclosure
vulnerability. An attacker can exploit this vulnerability by making a
POST request to files in a folder with both WebDAV and CGI enabled. 

*** Note that Nessus solely relied on the version number
*** of the remote server to issue this warning. This might
*** be a false positive." );
 script_set_attribute(attribute:"see_also", value:"http://www.apache.org/dist/httpd/CHANGES_2.0" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Apache web server version 2.0.43 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );

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
if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/2\.0\.([0-9][^0-9]|[0-3][0-9]|4[0-2])", string:serv))
 {
   security_warning(port);
 }
