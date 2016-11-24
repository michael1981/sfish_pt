#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(15436);
 script_version("$Revision: 1.11 $");
 script_cve_id("CVE-2004-0958");
 script_bugtraq_id(11334);
 script_xref(name:"OSVDB", value:"12601");

 script_name(english:"PHP php_variables.c Multiple Variable Open Bracket Memory Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"The remote server is affected by an information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of PHP which is older than 5.0.2 or
4.39.

The remote version of this software is affected by a memory disclosure
vulnerability in PHP_Variables.  An attacker may exploit this flaw to
remotely read portions of the memory of the httpd process on the
remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-5.php#5.0.2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PHP 5.0.2 or 4.3.9" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

 script_end_attributes();

 script_summary(english:"Checks for version of PHP");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl");
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

if(ereg(pattern:"PHP/([0-3]\..*|4\.([0-2]\.|3\.[0-8][^0-9])|5\.0\.[01][^0-9])", string:php))
   security_warning(port);
