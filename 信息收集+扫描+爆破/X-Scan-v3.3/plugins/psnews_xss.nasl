#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
#  Ref:  Michal Blaszczak <wacky nicponie org>
# This script is released under the GNU GPLv2

# Changes by Tenable:
# - Revised plugin title (5/28/09)


include("compat.inc");

if(description)
{
 script_id(14685);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2004-1665");
 script_bugtraq_id(11124);
 script_xref(name:"OSVDB", value:"9786");
 
 script_name(english:"PsNews index.php Multiple Parameter XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by
cross-site scripting issues. ");
 script_set_attribute(attribute:"description", value:
"The remote server is running a version of PsNews (a content management
system) which is older than 1.2. 

This version is affected by multiple cross-site scripting flaws.  An
attacker may exploit these to steal the cookies from legitimate users
of this website." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-09/0066.html" );
 script_set_attribute(attribute:"see_also", value:"http://mail.nessus.org/pipermail/nessus/2006-December/msg00024.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 
 summary["english"] = "check PsNews XSS flaws";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009  David Maciejak");
		
 family["english"] = "CGI abuses : XSS";

 script_family(english:family["english"]);
 script_dependencie("cross_site_scripting.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);
if(!port) exit(0);

if ( ! can_host_php(port:port) ) exit(0);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

if(get_port_state(port))
{
  foreach dir ( cgi_dirs() )
  {
  buf = http_get(item:dir + "/index.php?function=show_all&no=%253cscript>foo%253c/script>", port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);
  if(egrep(pattern:"<script>foo</script>", string:r))
  {
 	security_warning(port:port, extra:'The following URL is vulnerable :\n' + dir + "/index.php?function=show_all&no=%253cscript>foo%253c/script>");
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
  }
  buf = http_get(item:dir + "/index.php?function=add_kom&no=<script>foo</script>", port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);
  if(egrep(pattern:"<script>foo</script>", string:r))
  {
 	security_warning(port:port, extra:'The following URL is vulnerable :\n' + dir + "/index.php?function=add_kom&no=<script>foo</script>");
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
  }
 }
}
