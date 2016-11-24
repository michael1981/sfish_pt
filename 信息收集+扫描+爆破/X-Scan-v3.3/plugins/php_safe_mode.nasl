#
# (C) Tenable Network Security, Inc.
#

# References:
#
# Date: Fri, 23 Aug 2002 09:30:40 +0200 (CEST)
# From: "Wojciech Purczynski" <cliph@isec.pl>
# To: bugtraq@securityfocus.com
# Subject: PHP: Bypass safe_mode and inject ASCII control chars with mail()
# Message-ID:<Pine.LNX.4.44L.0208211118510.23552-100000@isec.pl>
#


include("compat.inc");

if(description)
{
 script_id(10701);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2001-1246");
 script_bugtraq_id(2954);
 script_xref(name:"OSVDB", value:"579");
 
 script_name(english:"PHP Safe Mode mail Function 5th Parameter Arbitrary Command Execution");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary commands may be run on the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PHP 4.0.5.

There is a flaw in this version of PHP that allows local users to 
circumvent the safe mode and to gain the UID of the HTTP process." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PHP 4.1.0" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P" );

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
banner = get_http_banner(port: port);
if(!banner) exit(0);
php = get_php_version(banner:banner);
if ( ! php ) exit(0);

if(ereg(pattern:"PHP/4\.0\.5.*", string:php))
   security_warning(port);
