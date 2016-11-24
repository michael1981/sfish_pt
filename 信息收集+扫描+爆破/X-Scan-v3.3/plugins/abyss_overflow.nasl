#
# (C) Tenable Network Security, Inc.
# 

include("compat.inc");

if(description)
{
 script_id(11784);
 script_cve_id("CVE-2003-1337");
 script_bugtraq_id(8062, 8064);
 script_xref(name:"OSVDB", value:"50471");

 script_version ("$Revision: 1.10 $");
 script_name(english:"Abyss Web Server GET Request Multiple Vulnerabilities");
 script_summary(english:"Tests the version of the remote Abyss server.");

 script_set_attribute(attribute:"synopsis",value:
"The remote web server is affected by multiple vulnerabilites.");

 script_set_attribute(attribute:"description",value:
"The remote Abyss Web server is earlier than version 1.1.6.  Such
versions are reportedly vulnerable to a buffer overflow which may be
exploited by an attacker to execute arbitrary code on the host. 

In addition, it is possible to inject malicious data into server
response headers using a specially crafted GET request.  An attacker
could use this vulnerability to launch cross-site scripting
attacks.");

 script_set_attribute(attribute:"see_also",value:
"http://archives.neohapsis.com/archives/bugtraq/2003-06/0235.html");

 script_set_attribute(attribute:"solution",value:
"Upgrading to Abyss 1.1.6 or newer is reported to fix the problem.");

 script_set_attribute(attribute:"cvss_vector",value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencies("find_service1.nasl", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

########

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

#
# I could not really reproduce the issue with 1.1.5, 
# so I'll stick to a banner check instead
#
banner = get_http_banner(port:port);
if(!banner)exit(0);
if(egrep(pattern:"^Server: Abyss/(0\..*|1\.(0\..*|1\.[0-5])) ", string:banner))
       security_hole(port);
exit(0);       
