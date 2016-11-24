#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
# Ref: Exoduks <exoduks@gmail.com> 
#
# This script is released under the GNU GPLv2

# Changes by Tenable:
# - Revised plugin title (4/28/09)


include("compat.inc");

if(description)
{
 script_id(14665);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2004-1659");
 script_bugtraq_id(11097);
 script_xref(name:"OSVDB", value:"9558");
 
 script_name(english:"CuteNews index.php mod Parameter XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to cross-
site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The version of CuteNews installed on the remote host is vulnerable to
a cross-site-scripting (XSS) attack.  An attacker, exploiting this
flaw, would need to be able to coerce a user to browse to a
purposefully malicious URI.  Upon successful exploitation, the
attacker would be able to run code within the web-browser in the
security context of the CuteNews server." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=109415338521881&w=2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
 script_summary(english:"Checks for the presence of index.php");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("cutenews_detect.nasl", "cross_site_scripting.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

if(!get_port_state(port))
	exit(0);
if(!can_host_php(port:port)) 
	exit(0);



# Test an install.
install = get_kb_item(string("www/", port, "/cutenews"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  loc = matches[2];

  req = http_get(item:string(loc, "/index.php?mod=<script>foo</script>"),
 		port:port);			
  r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
  if( r == NULL ) exit(0);
  if(egrep(pattern:"<script>foo</script>", string:r))
  {
 	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
  }
}
