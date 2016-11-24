#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# 
# Ref: Nick Gudov <cipher@s-quadra.com>
#
# This script is released under the GNU GPL v2

# Changes by Tenable:
# - Revised plugin title, changed family (4/28/09)


include("compat.inc");

if(description)
{
  script_id(15461);
  script_version("$Revision: 1.9 $");
  script_cve_id("CVE-2004-1881", "CVE-2004-1882");
  script_bugtraq_id(10019, 10020);
  script_xref(name:"OSVDB", value:"4785");
  script_xref(name:"OSVDB", value:"4786");
  script_xref(name:"OSVDB", value:"4787");
  
  script_name(english:"CactuShop 5.x Multiple Remote Vulnerabilities (XSS, SQLi)");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host runs CactuShop, an e-commerce web application written
in ASP.

The remote version of this software is vulnerable to cross-site 
scripting due to a lack of sanitization of user-supplied data in the 
script 'popuplargeimage.asp'.

Successful exploitation of this issue may allow an attacker to execute 
malicious script code on a vulnerable server. 

This version may also be vulnerable to SQL injection attacks in 
the scripts 'mailorder.asp' and 'payonline.asp'. The user-supplied 
input parameter 'strItems' is not filtered before being used in 
an SQL query. Thus the query modification through malformed input 
is possible.

Successful exploitation of this vulnerability can enable an attacker
to execute commands in the system (via MS SQL the function xp_cmdshell)." );
 script_set_attribute(attribute:"see_also", value:"http://marc.theaimsgroup.com/?l=bugtraq&amp;m=108075059013762&amp;w=2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to CactuShop 5.113 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

  script_summary(english:"Checks CactuShop flaws");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
  script_family(english:"CGI abuses");
  script_require_ports("Services/www", 80);
  script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
  exit(0);
}

#the code

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! get_port_state(port))exit(0);
if ( ! can_host_asp(port:port) ) exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

buf = http_get(item:"/popuplargeimage.asp?strImageTag=<script>foo</script> ", port:port);
r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
if( r == NULL )exit(0);

if(egrep(pattern:"<script>foo</script>", string:r))
{
  security_hole(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  exit(0);
}
