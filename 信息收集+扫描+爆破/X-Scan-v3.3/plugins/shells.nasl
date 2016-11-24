#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10252);
 script_version ("$Revision: 1.27 $");

 script_cve_id("CVE-1999-0509");
 script_xref(name:"OSVDB", value:"200");
 
 script_name(english:"Web Server /cgi-bin Shell Access");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary commands can be run on the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote web server has one of these shells installed
in /cgi-bin :
	ash, bash, csh, ksh, sh, tcsh, zsh

Leaving executable shells in the cgi-bin directory of
a web server may allow an attacker to execute arbitrary
commands on the target machine with the privileges of the 
HTTP daemon." );
 script_set_attribute(attribute:"solution", value:
"Remove all the shells from /cgi-bin." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();
 
 script_summary(english:"Checks for the presence of various shells in /cgi-bin");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);


port = get_http_port(default:80);


if(!get_port_state(port))exit(0);

sh = make_list("ash", "bash", "csh", "ksh", "sh", "tcsh", "zsh");
 
foreach dir (cgi_dirs())
{
 foreach s (sh)
 {
  ok = is_cgi_installed_ka(item:string(dir, "/", s), port:port);
  if(ok)
  {
   security_hole(port);
   exit(0);
  }
 }
}
