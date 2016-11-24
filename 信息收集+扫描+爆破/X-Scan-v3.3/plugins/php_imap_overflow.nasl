#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added link to the Bugtraq message archive
#


include("compat.inc");

if(description)
{
 script_id(10628);
 script_version ("$Revision: 1.17 $");
 script_bugtraq_id(6557);
 script_xref(name:"OSVDB", value:"522");

 script_name(english:"PHP < 4.0.4 IMAP Module imap_open() Function Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on this host." );
 script_set_attribute(attribute:"description", value:
"A version of PHP which is older than 4.0.4 is running on this host.

There is a buffer overflow condition in the IMAP module of this version
which may allow an attacker to execute arbitrary commands with the 
privileges of the web server, if this server is serving a webmail 
interface." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PHP 4.0.4" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/Mar/0040.html" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Checks for version of PHP");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
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
 
if(ereg(pattern:"PHP/4\.0\.[0-3][^0-9]", string:php))
   security_warning(port);
