#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40876);
  script_version("$Revision: 1.1 $");

  script_name(english:"Citrix Licensing Service Detection");
  script_summary(english:"Checks for Citrix Licensing Service");

  script_set_attribute(
    attribute:"synopsis",
    value:"A Citrix Licensing Service (lmgrd.exe) is listening on this port."
  );
  script_set_attribute(
    attribute:"description", 
    value:"The remote host is running Citrix Licensing Service."
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "If this service is not needed, disable it or filter incoming traffic\n",
      "to this port."
    )
  );
  script_set_attribute(
    attribute:"risk_factor", 
    value:"None"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 27000);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

port = 27000;
if (known_service(port:port)) exit(0, "Service on port "+port+" is already known.");
if (!get_tcp_port_state(port)) exit(1, "Port "+port+" is not open.");

soc = open_sock_tcp(port);
if (!soc) exit(1, "Can't connect to port "+port+".");

req = crap(data:'\x2f', length:0x14);;
send(socket:soc, data:req);
buf = recv(socket:soc, length:88);
if (strlen(buf) == 0) exit(0, "No response.");

if ("57ea2d36300000" >< hexstr(buf))
{
  register_service (port:port, proto:"lmgrd");
  security_note(port);
}
