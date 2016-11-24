#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  ref : Oliver Karow <oliver.karow@gmx.de>
#  This script is released under the GNU GPL v2
#

include("compat.inc");

if(description)
{
 script_id(18213);
 script_version("$Revision: 1.7 $");

 script_cve_id("CVE-2005-1118");
 script_bugtraq_id(13168);
 script_xref(name:"OSVDB", value:"15513");
 
 script_name(english:"RSA Security RSA Authentication Agent For Web For IIS XSS");

 script_set_attribute(
  attribute:"synopsis",
  value:
"A web application on the remote host has a cross-site scripting
vulnerability."
 );
 script_set_attribute(
  attribute:"description",
  value:
"The remote host appears to be running RSA Authentication Agent for
Web for IIS.

The remote version of this application fails to adequately sanitize
input to the 'postdata' variable of IISWebAgentIF.dll.  A remote
attacker could exploit this by tricking a user into requesting a
maliciously crafted URL."
 );
 script_set_attribute(
  attribute:"see_also",
  value:"http://www.oliverkarow.de/research/rsaxss.txt"
 );
 script_set_attribute(
  attribute:"solution",
  value:"Upgrade to RSA Authentication Agent for Web for IIS 5.3 or later."
 );
 script_set_attribute(
  attribute:"cvss_vector",
  value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N"
 );
 script_end_attributes();

 script_summary(english:"Test for XSS flaw in RSA Security RSA Authentication Agent For Web");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"This script is Copyright (C) 2005-2009 David Maciejak");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

req = http_get(item:'/WebID/IISWebAgentIF.dll?postdata="><script>foo</script>', port:port);
res = http_keepalive_send_recv(port:port, data:req);
if( res == NULL ) exit(0);
if ("<TITLE>RSA SecurID " >< res && ereg(pattern:"<script>foo</script>", string:res) )
{
       security_warning(port);
       set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}

