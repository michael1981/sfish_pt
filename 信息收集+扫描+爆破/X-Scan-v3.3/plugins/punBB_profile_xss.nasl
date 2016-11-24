#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  This script is released under the GNU GPLv2
#


include("compat.inc");

if(description)
{
 script_id(15940);
 script_version ("$Revision: 1.9 $"); 
 script_bugtraq_id(11847);
 script_xref(name:"OSVDB", value:"7975");

 script_name(english:"PunBB profile.php XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to multiple
cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of PunBB installed on the remote
host fails to properly sanitize user input to the script
'profile.php'.  With a specially-crafted URL, an attacker can inject
arbitrary HTML and script code into a user's browser, resulting in a
loss of integrity, theft of authentication cookies, and the like." );
 script_set_attribute(attribute:"see_also", value:"http://www.punbb.org/changelogs/1.1.3_to_1.1.4.txt" );
 script_set_attribute(attribute:"solution", value:
"Update to PunBB version 1.1.4 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 
 script_summary(english:"Checks for PunBB profile.php XSS");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 
 script_family(english:"CGI abuses : XSS");
 script_dependencie("punBB_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/punBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (egrep(pattern: "^(0\.|1\.0|1\.1[^.]|1\.1\.[0123]([^0-9]|$))",string:ver))
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
