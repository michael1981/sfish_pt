#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# 
# Ref: James Bercegay of the GulfTech Security Research Team
# This script is released under the GNU GPLv2

# Changes by Tenable:
# - Revised plugin title (9/4/09)


include("compat.inc");

if(description)
{
  script_id(14647);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2004-1645");
  script_bugtraq_id(11071);
  script_xref(name:"OSVDB", value:"9388");
  script_xref(name:"OSVDB", value:"9389");
  script_xref(name:"OSVDB", value:"9390");
  script_xref(name:"Secunia", value:"12418");

  script_name(english:"Xedus Webserver Multiple XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web server with a
cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host runs Xedus Peer to Peer webserver.
This version is vulnerable to cross-site scripting attacks.

With a specially crafted URL, an attacker can cause arbitrary
code execution resulting in a loss of integrity." );
 script_set_attribute(attribute:"see_also", value:"http://www.gulftech.org/?node=research&article_id=00047-08302004" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version and 
remove .x files located in ./sampledocs folder" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );
script_end_attributes();


  script_summary(english:"Checks XSS in Xedus");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
  script_dependencies("xedus_detect.nasl", "cross_site_scripting.nasl");
  script_family(english:"Peer-To-Peer File Sharing");
  script_require_ports("Services/www", 4274);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:4274);
if ( ! get_kb_item("xedus/" + port + "/running")) exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

if(get_port_state(port))
{
 soc = http_open_socket(port);
 if(soc)
 {
  buf = http_get(item:"/test.x?username=<script>foo</script>", port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);
  if(egrep(pattern:"<script>foo</script>", string:r))
  {
 	http_close_socket(soc);
 	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
  }
  buf = http_get(item:"/TestServer.x?username=<script>foo</script>", port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);
  if(egrep(pattern:"<script>foo</script>", string:r))
  {
 	http_close_socket(soc);
 	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
  }
  buf = http_get(item:"/testgetrequest.x?param=<script>foo</script>", port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);
  if(egrep(pattern:"<script>foo</script>", string:r))
  {
 	http_close_socket(soc);
 	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
  }
  http_close_socket(soc);
 }
}
exit(0);
