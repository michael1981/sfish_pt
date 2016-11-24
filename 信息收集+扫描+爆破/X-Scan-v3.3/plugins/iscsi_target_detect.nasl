#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29700);
  script_version("$Revision: 1.4 $");

  script_name(english:"iSCSI Target Detection");
  script_summary(english:"Logs in and discovers targets");

 script_set_attribute(attribute:"synopsis", value:
"A storage area network service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service supports the iSCSI (Internet Small Computer Systems
Interface) protocol, which encapsulates the SCSI protocol over TCP/IP
and allows sharing remote devices, known as 'targets', over a local-
or wide-area network." );
 script_set_attribute(attribute:"see_also", value:"http://www.faqs.org/rfcs/rfc3720.html" );
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/ISCSI" );
 script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired." );
 script_set_attribute(attribute:"risk_factor", value:
"None" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 3260);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") )
{
  port = get_unknown_svc(3260);
  if (!port) exit(0);
}
else port = 3260;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Send a login request.
set_byte_order(BYTE_ORDER_BIG_ENDIAN);

initiator = string("iqn.2007-12.com.nessus.nasl:", SCRIPT_NAME);
isid = mkbyte(0x80) + mkword(0x1234) + mkbyte(0x56) + mkword(0x7890);
statsn = 0;
task = 1;

keys = string(
  "InitiatorName=", initiator, mkbyte(0),
  "SessionType=Discovery", mkbyte(0),
  "AuthMethod=None", mkbyte(0)
);

req = 
  mkbyte(0x43) +                       # opcode (0x43 => login request w/ immediate delivery)
  mkbyte(0x83) +                       # T, C, CSG and NSG
  mkbyte(0x00) +                       # VersionMax
  mkbyte(0x00) +                       # VersionMin
  mkbyte(0x00) +                       # TotalAHSLength
  mkbyte(strlen(keys) >> 16) +         # Data segment length
    mkword(strlen(keys) & 0xffff) +
  isid +
  mkword(0x00) +                       # TSIH
  mkdword(task) +                      # InitiatorTaskTag
  mkword(0x00) +                       # CID
  mkword(0x00) +                       # reserved
  mkdword(0x00) +                      # CmdSN
  mkdword(statsn) +                    # ExpStatSN
  crap(data:mkbyte(0), length:16) +    # reserved
  keys;                                # Data segment
if (strlen(req) % 4) req += crap(data:mkbyte(0), length:4-strlen(req)%4);
send(socket:soc, data:req);
res = recv(socket:soc, length:1024, min:48);


# If ...
if (
  # the response is long-enough and ...
  strlen(res) >= 48 &&
  # the opcode indicates a login response and ...
  getbyte(blob:res, pos:0) == 0x23 &&
  # the status indicates a success and ...
  0 == getword(blob:res, pos:0x24) &&
  # the StatSN is what we expected
  statsn == getdword(blob:res, pos:0x18)
)
{
  # Try to get a list of targets.
  info = "";

  if (getbyte(blob:res, pos:1) & 3 == 3)
  {
    keys = "SendTargets=All" + mkbyte(0);
    statsn += 1;
    task += 1;

    req = 
      mkbyte(0x44) +                   # opcode (text request w/ immediate delivery)
      mkbyte(0x80) +                   # flags
      mkword(0x00) +                   # reserved
      mkbyte(0x00) +                   # TotalAHSLength
      mkbyte(strlen(keys) >> 16) + 
        mkword(strlen(keys) & 0xffff) +
      crap(data:mkbyte(0), length:8) + # LUN
      mkdword(task) +                  # Initiator Task Tag
      mkdword(0xffffffff) +            # constant
      mkdword(0x00) +                  # CmdSN
      mkdword(statsn) +                # ExpStatSN
      crap(data:mkbyte(0), length:16) + # reserved
      keys;                            # Data segment
    if (strlen(req) % 4) req += crap(data:mkbyte(0), length:4-strlen(req)%4);
    send(socket:soc, data:req);
    res = recv(socket:soc, length:1024, min:48);

    if (
      # the response is long-enough and...
      strlen(res) >= 48 &&
      # the opcode indicates a text response and...
      getbyte(blob:res, pos:0) == 0x24 &&
      # the StatSN is what we expected
      statsn == getdword(blob:res, pos:0x18)
    )
    {
      # If the data segment length is non-zero.
      if ((getbyte(blob:res, pos:5) << 16) + getword(blob:res, pos:6) == 0)
      {
        info = "The remote server does not have any iSCSI targets.\n";
      }
      else
      {
        info = string(
          "The remote server has the following list of iSCSI targets :\n",
          "\n"
        );

        while ("TargetName=" >< res)
        {
          res = strstr(res, "TargetName=") - "TargetName=";
          i = stridx(res, mkbyte(0));
          if (i > 0) info += "  " + substr(res, 0, i-1) + '\n';
        }
      }
    }
  }

  # Logout.
  task += 1;

  req = 
    mkbyte(0x46) +                     # opcode (0x46 => logout request w/ immediate delivery)
    mkbyte(0x80) +                     # close session
    mkbyte(0x00) +                     # TotalAHSLength
    mkword(0) + mkbyte(0) +            # Data segment length
    crap(data:mkbyte(0), length:8) +   # reserved
    mkword(0x00) +                     # TSIH
    mkdword(task) +                    # Initiator Task Tag
    mkword(0x00) +                     # CID
    mkword(0x00) +                     # reserved
    mkdword(0x00) +                    # CmdSN
    mkdword(0) +                       # ExpStatSN
    crap(data:mkbyte(0), length:16);   # reserved
  send(socket:soc, data:req);
  res = recv(socket:soc, length:1024, min:48);

  close(soc);

  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"iscsi-target");

  if (info)
    security_note(port:port, extra:info);
  else
    security_note(port:port);
}

