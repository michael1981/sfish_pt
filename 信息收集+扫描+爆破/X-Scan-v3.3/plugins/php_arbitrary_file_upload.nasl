#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14770);
 script_version("$Revision: 1.7 $");
 script_cve_id("CVE-2004-0959");
 script_bugtraq_id(11190);
 script_xref(name:"OSVDB", value:"12603");

 script_name(english:"PHP rfc1867.c $_FILES Array Crafted MIME Header Arbitrary File Upload");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary files may be uploaded on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of PHP which is older than 4.3.9 or
5.0.2. 

The remote version of this software is affected by an unspecified file
upload vulnerability which may allow an local attacker to upload 
arbitrary files to the server.

** This flaw can only be exploited locally." );
# Link is dead
# script_set_attribute(attribute:"see_also", value:"http://viewcvs.php.net/viewcvs.cgi/php-src/NEWS.diff?r1=1.1247.2.724&r2=1.1247.2.726" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PHP 4.3.9 or 5.0.2" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 script_summary(english:"Checks for version of PHP");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
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
 if (! php) exit(0);
 if(ereg(pattern:"PHP/(4\.([0-2]\..*|3\.[0-8])|5\.0\.[01])[^0-9]", string:php))
   security_note(port);
