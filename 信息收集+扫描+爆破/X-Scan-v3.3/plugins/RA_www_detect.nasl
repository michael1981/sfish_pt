#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Broken link deleted


include("compat.inc");

if(description)
{
  script_id(10920);
  script_version ("$Revision: 1.17 $");
 
  script_name(english:"RemotelyAnywhere WWW Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"A web server is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The RemotelyAnywhere WWW server is running on this system.
According to NAVCIRT, attackers target love this management tool." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/isn/2002-q1/0419.html" );
 script_set_attribute(attribute:"solution", value:
"If you installed it, ignore this warning. If not, your machine is 
likely compromised by an attacker." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_end_attributes();

  script_summary(english:"Detect RemotelyAnywhere www server");
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
  script_family(english:"Backdoors");
  script_dependencie("find_service1.nasl", "http_version.nasl");
  script_require_ports("Services/www", 2000, 2001);
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

ports = add_port_in_list(list:get_kb_list("Services/www"), port:2000);
ports = add_port_in_list(list:ports, port:2001);

foreach port (ports)
{
 banner = get_http_banner(port:port);

 if (! banner) exit(0);

 if (egrep(pattern:"^Server: *RemotelyAnywhere", string:banner))
 {
  security_note(port);
 }
}
# TBD: check default account administrator / remotelyanywhere
