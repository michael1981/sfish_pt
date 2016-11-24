#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# Ref: Lostmon <lostmon@gmail.com>
#
# This script is released under the GNU GPLv2
#

# Changes by Tenable:
# - Revised plugin title, changed family (4/28/09)


include("compat.inc");

if(description)
{
 script_id(15717);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2004-2245", "CVE-2004-2246");
 script_bugtraq_id(11587);
 script_xref(name:"OSVDB", value:"11318");
 script_xref(name:"OSVDB", value:"11319");
 script_xref(name:"OSVDB", value:"11320");
 script_xref(name:"OSVDB", value:"11624");
 
 script_name(english:"Goollery < 0.04b Multiple Vulnerabilities");
 script_summary(english:"Checks fot the presence of Goollery XSS flaw in viewpic.php");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected by
a cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"Goollery, a GMail based photo gallery written in PHP, 
is installed on this remote host.

According to it's version number, this host is vulnerable to multiple
cross-site-scripting (XSS) attacks; eg, through the 'viewpic.php'
script.  An attacker, exploiting these flaws, would need to be able to
coerce a user to browse a malicious URI.  Upon successful exploitation,
the attacker would be able to run code within the web-browser in the
security context of the remote server." );
 script_set_attribute(attribute:"see_also", value:"http://osvdb.org/ref/11/11xxx-goollery_multiple.txt" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Goollery 0.04b or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);
if(!can_host_php(port:port)) exit(0);

function check(loc)
{
  local_var r, req;

  req = http_get(item:string(loc, "/viewpic.php?id=7&conversation_id=<script>foo</script>&btopage=0"), port:port); 	 
  r = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if( r == NULL ) exit(0);

  if(
    egrep(pattern:"^HTTP/1\.[01] +200 ", string:r) && 
    egrep(pattern:"<script>foo</script>", string:r)
  )
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}

dir = make_list(cgi_dirs(),"/goollery");
foreach d (dir)	
{
 	check(loc:d);
}
