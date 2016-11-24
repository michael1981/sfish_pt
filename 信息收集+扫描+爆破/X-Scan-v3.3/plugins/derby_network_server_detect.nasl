#
# (C) Tenable Network Security
#

include("compat.inc");

if (description)
{
  script_id(22410);
  script_version("$Revision: 1.4 $");

  script_name(english:"Derby Network Server Detection");
  script_summary(english:"Detects a Derby Network Server");

 script_set_attribute(attribute:"synopsis", value:
"A Derby Network Server is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a Derby (formerly Cloudscape) Network
Server, which allows for network access to the Derby database engine
on that host.  Derby itself is a Java-based relational database
developed by the Apache foundation." );
 script_set_attribute(attribute:"see_also", value:"http://db.apache.org/derby/" );
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Apache_Derby" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 1527);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery")  ) {
  port = get_unknown_svc(1527);
  if (!port) exit(0);
}
else port = 1527;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Probe the service.
#
# nb: this is based on NetworkServerControlImpl.java from Derby's source.
req = "CMD:" +                         # command header
  mkword(1) +                          # protocol version
  mkbyte(0) +                          # locale
  mkbyte(0) +                          # always zero
  mkbyte(6);                           # command (6 => sysinfo)
raw_string("CMD:", 0x00, 0x01, 0x00, 0x00, 0x06);
send(socket:soc, data:req);
res = recv(socket:soc, length:4096);


# If...
if (
  # the response is long enough and...
  strlen(res) > 6 &&
  # it starts with a reply header and..
  substr(res, 0, 3) == "RPY:" &&
  # the word at pos 5 is the length of the message and
  getword(blob:res, pos:5) == (strlen(res) - 7) &&
  # the message has either...
  (
    # an error because we're not on the loopback interface or...
    "DRDA_NeedLocalHost" >< res ||
    # a response to the sysinfo command
    "Network Server Information" >< res
  )
)
{
  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"derby");
  if ("DRDA_NeedLocalHost" >< res)
   set_kb_item(name: "derby/blocked/"+port, value: TRUE);
  security_note(port);
}
