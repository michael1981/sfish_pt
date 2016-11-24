#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# 
# Ref: Oliver Karow <Oliver Karow gmx de>
#
# This script is released under the GNU GPL v2

# Changes by Tenable
# - Updated to use compat.inc (11/20/2009)


include("compat.inc");

if(description)
{
  script_id(17972);
  script_cve_id("CVE-2005-1006");
  script_bugtraq_id(12984);
  script_xref(name:"OSVDB", value:"15261");
  script_xref(name:"OSVDB", value:"15262");
  script_version("$Revision: 1.8 $");
  
  script_name(english:"SonicWall SOHO Web Interface XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple cross-site scripting
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is a SonicWall SOHO appliance.

This version is vulnerable to multiple flaws, and in particular to a
cross-site scripting due to a lack of sanitization of user-supplied data.
Successful exploitation of this issue may allow an attacker to execute 
malicious script code on a vulnerable appliance." );
 script_set_attribute(attribute:"see_also", value:"http://www.sonicwall.com/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

  script_summary(english:"Checks SonicWall SOHO Web Interface XSS");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
  script_family(english:"CGI abuses : XSS");
  script_require_ports("Services/www",80);
  script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
  exit(0);
}

#the code

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! get_port_state(port))exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

buf = http_get(item:"/<script>foo</script>", port:port);
r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1, embedded:TRUE);
if( r == NULL )exit(0);

#if(egrep(pattern:"<title>SonicWall</title>.*<script>foo</script>", string:r))
if(egrep(pattern:"SonicWall", string:r, icase:TRUE) &&
   egrep(pattern:"<script>foo</script>", string:r))
{
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  exit(0);
}
