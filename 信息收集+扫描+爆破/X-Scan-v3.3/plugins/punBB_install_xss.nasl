#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  This script is released under the GNU GPLv2
#


include("compat.inc");

if(description)
{
 script_id(15939);
 script_version ("$Revision: 1.10 $"); 
 script_bugtraq_id(11845);
 script_xref(name:"OSVDB", value:"7976");

 script_name(english:"PunBB < 1.1.2 install.php XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
several cross-site scripting vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote version of PunBB is vulnerable to cross-site scripting
flaws through 'install.php' script.  With a specially-crafted URL, an
attacker can inject arbitrary HTML and script code into a user's
browser resulting in the possible theft of authentication cookies,
mis-representation of site contents, and the like." );
 script_set_attribute(attribute:"see_also", value:"http://www.punbb.org/changelogs/1.1.1_to_1.1.2.txt" );
 script_set_attribute(attribute:"solution", value:
"Update to PunBB version 1.1.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 
 script_summary(english:"Checks for PunBB install.php XSS");
 
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

  if (egrep(pattern: "^(0\.|1\.0|1\.1[^.]|1\.1\.1)",string:ver))
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
