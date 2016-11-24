#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  This script is released under the GNU GPLv2
#

# Changes by Tenable:
# - Revised plugin title (3/31/2009)


include("compat.inc");

if(description)
{
 script_id(15938);
 script_version ("$Revision: 1.6 $"); 
 script_bugtraq_id(11841);
 script_xref(name:"OSVDB", value:"7974");

 script_name(english:"PunBB Search Dropdown Private Forum Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to an
information disclosure flaw." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote version of PunBB reportedly may
include protected forums in a search dropdown list regardless of
whether a user has permissions to view those forums." );
 script_set_attribute(attribute:"see_also", value:"http://www.punbb.org/changelogs/1.1.4_to_1.1.5.txt" );
 script_set_attribute(attribute:"solution", value:
"Update to PunBB version 1.1.5 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 script_summary(english:"Checks for PunBB version for information disclosure");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 
 script_family(english:"CGI abuses");
 script_dependencie("punBB_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include('http_func.inc');

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/punBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  if (egrep(pattern: "^(0\.|1\.0|1\.1[^.]|1\.1\.[1-4]([^0-9]|$))",string:ver))
  {
    security_warning(port);
    exit(0);
  }
}
