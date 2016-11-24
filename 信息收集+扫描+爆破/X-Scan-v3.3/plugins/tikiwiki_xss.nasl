#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# 
# Ref: Florian Hengartner <hengartnerf@users.sourceforge.net>
# This script is released under the GNU GPLv2
#

include("compat.inc");

if(description)
{
  script_id(15709);
  script_bugtraq_id(14121);
  if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:7449);
  
  script_version("$Revision: 1.8 $");
  script_name(english:"TikiWiki tiki-error.php XSS");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application on the remote host has a cross-site scripting
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running TikiWiki, a content management system
written in PHP.

The version of this software running on the remote host has a
cross-site scripting vulnerability in tiki-error.php.  A remote
attacker could exploit this by tricking a user into requesting a
maliciously crafted URL, resulting in the execution of arbitrary
script code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5db4ca63"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to TikiWiki 1.7.8 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N"
  );
  script_end_attributes();

  script_summary(english:"Checks TikiWiki version");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
  script_family(english:"CGI abuses : XSS");
  script_dependencie("http_version.nasl");
  script_require_ports("Services/www");
 script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

#now the code

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

function check(loc)
{
 local_var r, req;
 req = http_get(item: loc + "/tiki-index.php", port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if( "This is Tiki v" >< r && egrep(pattern:"This is Tiki v(0\.|1\.[0-6]\.|1\.7\.[0-7][^0-9])", string:r) )
 {
 	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}

