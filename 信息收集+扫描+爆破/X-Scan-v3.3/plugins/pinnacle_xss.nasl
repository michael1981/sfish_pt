#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# 
# Ref: Secunia Research
#
# This script is released under the GNU GPLv2
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (5/27/09)


include("compat.inc");

if(description)
{
  script_id(15485);
  script_version("$Revision: 1.14 $");
  script_cve_id("CVE-2004-1700");
  script_bugtraq_id(11415);
  script_xref(name:"OSVDB", value:"10726");

  script_name(english:"Pinnacle ShowCenter SettingsBase.php Skin Parameter XSS");

 script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to cross site scripting." );
 script_set_attribute(attribute:"description", value:
"The remote host runs the Pinnacle ShowCenter web based interface.

The remote version  of this software is vulnerable to cross-site 
scripting attack due to a lack of sanity checks on skin parameter
in the SettingsBase.php script.

With a specially crafted URL, an attacker can cause arbitrary
code execution resulting in a loss of integrity." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the newest version of this software." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();


  script_summary(english:"Checks skin XSS in Pinnacle ShowCenter");
  script_category(ACT_GATHER_INFO);
  
  script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
  script_family(english:"CGI abuses : XSS");
  script_dependencie("cross_site_scripting.nasl"); 
  script_require_ports("Services/www", 8000);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8000);
if(!can_host_php(port:port)) exit(0);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

buf = http_get(item:"/ShowCenter/SettingsBase.php?Skin=<script>foo</script>", port:port);
r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
if( r == NULL )exit(0);

if(egrep(pattern:"<script>foo</script>", string:r))
{
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}
