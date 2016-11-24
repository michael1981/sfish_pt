#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27627);
  script_version("$Revision: 1.4 $");

  script_name(english:"HP OVCM Notify Daemon Detection");
  script_summary(english:"Sends an inventory request");

 script_set_attribute(attribute:"synopsis", value:
"A remote control service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service is an HP OVCM (formerly Radia) Notify Daemon, a
component of HP OpenView Configuration Management and OpenView Client
Configuration Management for managing computers." );
 script_set_attribute(attribute:"see_also", value:"http://openview.hp.com/" );
 script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 3465);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") )
{
  port = get_unknown_svc(3465);
  if (!port) exit(0);
}
else port = 3465;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Send a query.
uid = "NESSUS";
pass = rand_str();
cmd = string(
  "radskman ",
    "sname=DISCOVER_INVENTORY,",
    "dname=AUDIT,",
    "startdir=SYSTEM,",
    "rtimeout=7200,",
    "port=3464,",
    "ip=", this_host(), ",",
    "cop=y,",
    "mnt=y,",
    "JOBID=N:79:80"
);

req = mkbyte(0) +                       # listening port on nessusd host
  uid + mkbyte(0) +                     # user
  pass + mkbyte(0) +                    # pass (encrypted)
  cmd + mkbyte(0);                      # command to launch
send(socket:soc, data:req);
res = recv(socket:soc, length:1024, min:128);
close(soc);


# Register and report the service if we see a valid result.
if (
  strlen(res) && 
  getbyte(blob:res, pos:0) == 1 &&
  stridx(res, "Invalid credentials specified."+mkbyte(0)) == 1
)
{
  register_service(port:port, proto:"radexecd");
  security_note(port);
}
