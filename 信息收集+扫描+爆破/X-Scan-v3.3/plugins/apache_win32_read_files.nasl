#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11210);
 script_bugtraq_id(6660);
 script_cve_id("CVE-2003-0017");
 script_xref(name:"OSVDB", value:"9710");
 script_xref(name:"Secunia", value:"20493");
 script_xref(name:"IAVA", value:"2003-t-0003"); 
 script_version("$Revision: 1.13 $");
 
 script_name(english:"Apache < 2.0.44 Illegal Character Default Script Mapping Bypass");
 script_summary(english:"Requests /< and gets the output");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a request file disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running a version of Apache for Windows
which is older than 2.0.44. Such versions are reportedly affected by a
flaw which alloows an attacker to read files that they should not have
access to by appending special characters to them." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Apache 2.0.44 or newer." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=apache-httpd-announce&m=104313442901017&w=2" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
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

port = get_http_port(default:80);

 banner = get_http_banner(port: port);
 if(!banner)exit(0);
 if("Server: Apache" >< banner && "Apache/2.2" >!< banner && "Win32" >< banner )
 {
  r = http_send_recv3(method:"GET", item:"/<<<<<<<<<<<<", port:port);
  # Apache 2.0.44 replies with a code 403
  if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 301 ", string:r[0]))security_warning(port);
 }

