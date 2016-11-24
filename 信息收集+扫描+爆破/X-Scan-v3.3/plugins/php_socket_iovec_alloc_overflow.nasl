#
# (C) Tenable Network Security, Inc.
#

# Ref:
#
# Date: Tue, 25 Mar 2003 14:31:59 +0000
# From: Sir Mordred <mordred@s-mail.com>
# To: bugtraq@securityfocus.com
# Subject: @(#)Mordred Labs advisory - Integer overflow in PHP socket_iovec_alloc() function



include("compat.inc");

if(description)
{
 script_id(11468);
 script_version("$Revision: 1.20 $");
 script_cve_id("CVE-2003-0166");
 script_bugtraq_id(7187, 7197, 7198, 7199, 7256, 7259);
 script_xref(name:"OSVDB", value:"13393");
 script_xref(name:"OSVDB", value:"13394");
 script_xref(name:"OSVDB", value:"13395");
 script_xref(name:"OSVDB", value:"13396");

 script_name(english:"PHP socket_iovec_alloc() Function Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of PHP which is older than 4.3.2

There is a flaw in this version which may allow an attacker who has the 
ability to inject an arbitrary argument to the function 
socket_iovec_alloc() to crash the remote service and possibly to execute 
arbitrary code.

For this attack to work, PHP has to be compiled with the option
--enable-sockets (which is disabled by default), and an attacker needs 
to be able to pass arbitrary values to socket_iovec_alloc().

Other functions are vulnerable to such flaws : openlog(), socket_recv(), 
socket_recvfrom() and emalloc()" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PHP 4.3.2" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Checks for version of PHP");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
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

if(ereg(pattern:"PHP/([1-3]\..*|4\.([0-2]\..*|3\.[0-1]))[^0-9]", string:php))
   security_warning(port);
