#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# This script is released under the GNU GPLv2
#

# Changes by Tenable:
# - Updated to use compat.inc (11/16/09)
# - Revised plugin title (4/15/09)


include("compat.inc");

if(description)
{
 script_id(18628);
 script_version ("$Revision: 1.7 $");
 script_bugtraq_id(14099);
 script_xref(name:"OSVDB", value:"11025");

 script_name(english:"YaPiG Password Protected Directory Bypass");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to an
information disclosure flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host is running YaPiG, a web-based image gallery written in
PHP. 

The remote version of this software contains a flaw that can let a
malicious user view images in password protected directories. 
Successful exploitation of this issue may allow an attacker to access
unauthorized images on a vulnerable server." );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/tracker/index.php?func=detail&aid=842990&group_id=93674&atid=605076" );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/tracker/index.php?func=detail&aid=843736&group_id=93674&atid=605076" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 script_summary(english:"Checks for YaPiG version");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2005-2009 David Maciejak");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if (!can_host_php(port:port)) exit(0);


if (thorough_tests) dirs = list_uniq(make_list("/yapig", "/gallery", "/photos", "/photo", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
	res = http_get_cache(item:string(dir, "/"), port:port);
	if (isnull(res)) exit(0);

	#Powered by <a href="http://yapig.sourceforge.net" title="Yet Another PHP Image Gallery">YaPig</a> V0.92b
 	if(egrep(pattern:"Powered by .*YaPig.* V0\.([0-8][0-9]($|[^0-9])|9([0-3]|4[a-u]))", string:res))
 	{
 		security_warning(port);
		exit(0);
	}
 
}
