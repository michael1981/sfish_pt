#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# 
# Ref: Marc Ruef <marc.ruef@computec.ch>
#
# This script is released under the GNU GPLv2
#


include("compat.inc");

if(description)
{
  script_id(14824);
  script_cve_id("CVE-2004-1699");
  script_bugtraq_id(11232);
  script_version("$Revision: 1.6 $");
  script_name(english:"Pinnacle ShowCenter Skin DoS");

 
 script_set_attribute(attribute:"synopsis", value:
"A remote application is vulnerable to a denial of service." );
 script_set_attribute(attribute:"description", value:
"The remote host runs the Pinnacle ShowCenter web based interface.

The remote version of this software is vulnerable to a remote denial of 
service due to a lack of sanity checks on skin parameter.

With a specially crafted URL, an attacker can deny service of the ShowCenter 
web based interface." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the newest version of this software." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();


  script_summary(english:"Checks skin DoS in Pinnacle ShowCenter");
  script_category(ACT_DENIAL);
  
  script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
  script_family(english:"CGI abuses");
  script_require_ports("Services/www", 8000);
  script_dependencies("http_version.nasl");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8000);
if ( ! port ) exit(0);

if(get_port_state(port))
{
 soc = http_open_socket(port);
 if(soc)
 {
  buf = http_get(item:"/ShowCenter/SettingsBase.php?Skin=ATKnessus", port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);
  #try to detect errors
  if(egrep(pattern:"Fatal error.*loaduserprofile.*Failed opening required", string:r))
  {
    security_warning(port);
  }
  http_close_socket(soc); 
 }
}
exit(0);
