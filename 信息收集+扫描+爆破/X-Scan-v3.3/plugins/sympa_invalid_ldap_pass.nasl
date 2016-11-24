#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
# This script is released under the GNU GPLv2

# Changes by Tenable:
# - Revised plugin description (4/7/2009)


include("compat.inc");

if(description)
{
 script_id(14299);
 script_version ("$Revision: 1.15 $"); 
 script_xref(name:"OSVDB", value:"8689");

 script_name(english:"Sympa wwsympa Invalid LDAP Password Remote DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is susceptible to a
denial of service attack." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the installation of Sympa on the
remote host contains a flaw in the processing of LDAP passwords.  A
successful attack would crash the sympa application." );
 script_set_attribute(attribute:"solution", value:
"Update to version 3.4.4.1 or newer" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
script_end_attributes();

 
 script_summary(english:"Checks sympa version");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"CGI abuses");
 script_dependencies("sympa_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");

# nb: banner checks of open-source software are prone to false-
#     positives so only run the check if reporting is paranoid.
if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/sympa"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  ver = matches[1];
  if (ver =~ "^3\.4\.3")
  {
    security_warning(port);
    exit(0);
  }
}
