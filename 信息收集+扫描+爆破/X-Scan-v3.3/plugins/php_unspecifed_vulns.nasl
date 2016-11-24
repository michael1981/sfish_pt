#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(18033);
 script_bugtraq_id(13143, 13163, 13164);
 script_version("$Revision: 1.12 $");
 script_name(english:"PHP < 4.3.11 / 5.0.3 Multiple Unspecified Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote server is affected by several vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of PHP that is older than 5.0.3
or 4.3.11. 

The remote version of this software is affected by a set of
vulnerabilities in the EXIF module which have been fixed by the PHP
Group." );
 script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-5.php#5.0.4" );
 script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-4.php#4.3.11" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PHP 5.0.3 or 4.3.11" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();

 script_summary(english:"Checks for version of PHP");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
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
 
if(egrep(pattern:"PHP/([0-3]\..*|4\.([0-2]\.|3\.([0-9][^0-9]|10[^0-9]))|5\.0\.[0-3][^0-9])", string:php))
   security_hole(port);
