#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11507);
 script_version("$Revision: 1.21 $");

 script_cve_id("CVE-2003-0132");
 script_bugtraq_id(7254, 7255);
 script_xref(name:"OSVDB", value:"9712");
 script_xref(name:"OSVDB", value:"56517");
 
 script_name(english:"Apache < 2.0.45 Multiple Vulnerabilities (DoS, File Write)");
 script_summary(english:"Checks for version of Apache");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Apache 2.x which is older than
2.0.45. Such versions are reportedly affected by multiple
vulnerabilities :

  - There is a denial of service attack which may allow an
    attacker to disable this server remotely.

  - The httpd process leaks file descriptors to child
    processes, such as CGI scripts. An attacker who has the
    ability to execute arbitrary CGI scripts on this server
    (including PHP code) would be able to write arbitrary
    data in the file pointed to (in particular, the log
    files)." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Apache web server version 2.0.45 or later." );
 script_set_attribute(attribute:"see_also", value:"http://www.apache.org/dist/httpd/CHANGES_2.0" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
 script_category(ACT_MIXED_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl");
 script_require_keys("www/apache", "Settings/ParanoidReport");
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

if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);

banner = get_backport_banner(banner:get_http_banner(port: port));
if(!banner)exit(0);
 
serv = strstr(banner, "Server");
if( safe_checks() )
{
if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/2\.0\.([0-9][^0-9]|[0-3][0-9]|4[0-4])", string:serv))
 {
   security_warning(port);
 }
}
else if(egrep(pattern:"Apache(-AdvancedExtranetServer)/2", string:serv))
{
 if ( egrep(pattern:"Apache(-AdvancedExtranetServer)?/([3-9]\.|2\.([1-9]|0\.([5-9][0-9]|4[6-9])))", string:serv) ) exit(0);


 soc = open_sock_tcp(port);
 for(i=0;i<101;i++)
 {
  n = send(socket:soc, data:'\r\n');
  if(n <= 0)exit(0);
 }

 r = http_recv_headers3(socket:soc);
 if(!r)security_warning(port);
 }
