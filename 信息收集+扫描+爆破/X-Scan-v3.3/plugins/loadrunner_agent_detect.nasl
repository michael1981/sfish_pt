#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(24326);
  script_version("$Revision: 1.7 $");

  script_name(english:"Mercury LoadRunner Agent Service Detection");
  script_summary(english:"Tries to initialize a connection to a Mercury LoadRunner Agent");

 script_set_attribute(attribute:"synopsis", value:
"A Mercury LoadRunner Agent is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"There is a Mercury LoadRunner Agent listening on the remote host. 
This agent enables a LoadRunner Controller to communicate with the
LoadRunner Load Generator on the remote host for performance testing." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7ea6b97b" );
 script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port to hosts using the LoadRunner Controller." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 443, 54345);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") ) {
  port = get_unknown_svc(54345);
  if (!port) exit(0);
}
else port = 54345;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


function mk_padded_string(str)
{
  return mkdword(strlen(str)) + str + crap(data:mkbyte(0), length:4-(strlen(str) % 4));
}


# Define some constants.
guid = base64(str:rand_str(length:17));
pid = rand() % 0xffff;
tid = rand() % 0xffff;
rand16 = crap(16);
server_name = "nessus";
server_ip = this_host();
server_port = get_source_port(soc);


# Initialize a connection.
#
# - first part.
req1 = mkdword(0x19);
send(socket:soc, data:req1);
# - second part.
req2_1 = guid + "0";

req2_2 = 
      mkdword(7) + 
      mk_padded_string(
        str:server_name + ";" + pid + ";" + tid
      ) +
      mk_padded_string(
        str:string(
          "(-server_type=8)",
          "(-server_name=", server_name, ")",
          "(-server_full_name=", server_name, ")",
          "(-server_ip_name=", server_ip, ")",
          "(-server_port=", server_port, ")",
          "(-server_fd_secondary=4)",
          "(-guid_identifier=", guid, ")"
        )
      ) +
      mkdword(0x7530);
req2_2 = mkdword(4 + strlen(req2_2)) + req2_2;
req2_2 = 
    mkdword(0x1c) +
    mkdword(0x05) + 
    mkdword(0x01) + 
    rand16 +
    req2_2;
req2_2 = mkdword(strlen(req2_2)) + req2_2;

req2 = req2_1 + req2_2;
send(socket:soc, data:req2);


# If the result is a dword and equal to 0x1c....
res = recv(socket:soc, length:4);
if (strlen(res) == 4 && getdword(blob:res, pos:0) == 0x1c)
{
  # Read the rest of the packet.
  res = recv(socket:soc, length:512);

  # If the first two dwords in that are 0x0c and 0x02...
  if (
    strlen(res) > 8 && 
    getdword(blob:res, pos:0) == 0x0c &&
    getdword(blob:res, pos:4) == 0x01
  )
  {
    # Register and report the service.
    register_service(port:port, ipproto:"tcp", proto:"loadrunner_agent");
    security_note(port);
  }
}


close(soc);
