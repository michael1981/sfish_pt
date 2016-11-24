#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(11793);
 script_bugtraq_id(8226);
 script_cve_id("CVE-2003-0460");
 script_xref(name:"OSVDB", value:"9715");
 script_xref(name:"OSVDB", value:"51612");
 script_xref(name:"OSVDB", value:"51613");

 script_version("$Revision: 1.18 $");
 
 script_name(english:"Apache < 1.3.28 Multiple Vulnerabilities (DoS, ID)");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running a version of
Apache which is older than 1.3.28

There are several flaws in this version, including a denial of service
in redirect handling, a denial of service with control character 
handling in the 'rotatelogs' utility and a file descriptor leak in 
third-party module handling.

*** Note that Nessus solely relied on the version number
*** of the remote server to issue this warning. This might
*** be a false positive" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 1.3.28" );
 script_set_attribute(attribute:"see_also", value:"http://www.apache.org/dist/httpd/Announcement.html" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C" );

script_end_attributes();

 
 summary["english"] = "Checks for version of Apache";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
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

banner = get_http_banner(port: port);
if(!banner)exit(0);
banner = get_backport_banner(banner:banner);
 
serv = strstr(banner, "Server:");
if(!serv)exit(0);
if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/(1\.([0-2]\.[0-9]|3\.([0-9][^0-9]|[0-1][0-9]|2[0-7]))).*Win32.*", string:serv))
 {
   security_hole(port);
 } 

