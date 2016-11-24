#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
# ref: Stefan Esser 
# This script is released under the GNU GPLv2

# Changes by Tenable:
# - Revised plugin title, family change (5/21/09)


include("compat.inc");

if(description)
{
 script_id(13650);
 script_version("$Revision: 1.12 $");
 script_cve_id("CVE-2004-0594","CVE-2004-0595");
 script_bugtraq_id(10724, 10725);
 script_xref(name:"OSVDB", value:"7870");
 script_xref(name:"OSVDB", value:"7871");

 script_name(english:"PHP < 4.3.8 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by several vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of PHP 4.3 which is older or equal 
to 4.3.7.

PHP is a scripting language which acts as a module for Apache or as a 
standalone interpreter. There is a bug in the remote version of this 
software which may allow an attacker to execute arbitrary code on the 
remote host if the option memory_limit is set. Another bug in the 
function strip_tags() may allow an attacker to bypass content 
restrictions when submitting data and may lead to cross-site scripting
issues." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PHP 4.3.8" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"Checks for version of PHP");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"CGI abuses");
 if ( !defined_func("bn_random") )
 	script_dependencie("http_version.nasl");
 else
	script_dependencie("http_version.nasl", "redhat-RHSA-2004-392.nasl", "redhat-RHSA-2004-395.nasl");

 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("backport.inc");

if ( get_kb_item("CVE-2004-0594") || get_kb_item("CVE-2004-0595") ) exit(0);

port = get_http_port(default:80);
banner = get_http_banner(port:port);
if(!banner)exit(0);
php = get_php_version(banner:banner);
if (! php ) exit(0);

if(ereg(pattern:"PHP/4\.3\.[0-7][^0-9]", string:php))
{
   security_warning(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}

