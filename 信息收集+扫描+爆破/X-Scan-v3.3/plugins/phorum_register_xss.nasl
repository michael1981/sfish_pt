#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref: Scott Dewey
#
#  This script is released under the GNU GPL v2
#

# Changes by Tenable:
# - Revised plugin title, removed unrelated OSVDB refs (5/21/09)


include("compat.inc");

if (description) {
script_id(19584);
script_version("$Revision: 1.5 $");

script_cve_id("CVE-2005-2836");
script_bugtraq_id(14726);
script_xref(name:"OSVDB", value:"19155");

script_name(english:"Phorum register.php Username Field XSS");

 script_set_attribute(attribute:"synopsis", value:
"A remote CGI is vulnerable to cross site scripting." );
 script_set_attribute(attribute:"description", value:
"The remote version of Phorum contains a script called 'register.php'
which is vulnerable to a cross-site scripting attack.  An attacker may
exploit this problem to steal the authentication credentials of third
party users." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2005-09/0018.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Phorum 5.0.18 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();


script_summary(english:"Checks for cross-site scripting vulnerability in Phorum's register.php");
script_category(ACT_GATHER_INFO);
script_copyright(english:"This script is Copyright (C) 2005-2009 David Maciejak");
script_family(english:"CGI abuses : XSS");
script_dependencie("phorum_detect.nasl");
script_require_ports("Services/www", 80);

exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


install = get_kb_item(string("www/", port, "/phorum"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^([0-4]\..*|5\.0\.([0-9][^0-9]*|1[0-7][^0-9]*))$")
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
