#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25423);
  script_version("$Revision: 1.4 $");

  script_name(english:"SNMPc Management Server Default Credentials");
  script_summary(english:"Tries to login to SNMPc Management Server");

 script_set_attribute(attribute:"synopsis", value:
"The remote service is protected with default credentials." );
 script_set_attribute(attribute:"description", value:
"The SNMPc Management Server installation on the remote host uses a
default username / password combination to control access to its
administrative console.  Knowing these, an attacker can gain control
of the affected application." );
 script_set_attribute(attribute:"solution", value:
"Assign a password to the 'Administrator' User Profile using the SNMPc
Management Console." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("snmpc_crserv_detect.nasl");
  script_require_ports("Services/crserv", 165);

  exit(0);
}


include("byte_func.inc");
include("misc_func.inc");


port = get_kb_item("Services/crserv");
if (!port) port = 165;
if (!get_port_state(port)) exit(0);


# Establish a connection.
soc = open_sock_tcp(port);
if (!soc) exit(0);


user = "Administrator";
pass = "";
seq = rand() % 0xffff;
set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);


# Initiate a connection
init = 
  mkword(seq) + 
  mkword(0x00) +
  mkbyte(0x51) +
  mkbyte(0x03) +
  mkword(0x00) +
  mkdword(0x02) +
  "rcon";
init = mkdword(strlen(init) + 4) + init;
send(socket:soc, data:init);
res = recv(socket:soc, length:1024);


# If the response looks ok...
if (
  (strlen(res) > 4 && getdword(blob:res, pos:0) == strlen(res)) &&
  getword(blob:res, pos:4) == seq &&
  getdword(blob:res, pos:8) == 0xffffffff
) 
{
  # Try to log in.
  seq += 1;
  req = 
    mkword(seq) + 
    mkword(0x00) +
    mkbyte(0x52) +
    mkbyte(0x03) +
    mkword(0x00) +
    mkdword(0x02) +
    user + mkbyte(0x09) +
    pass + mkbyte(0x09) +
    mkword(0x30);
  req = mkdword(strlen(req) + 4) + req;
  send(socket:soc, data:req);
  res = recv(socket:soc, length:1024);

  # There's a problem if we were successful.
  if (
    (strlen(res) > 4 && getdword(blob:res, pos:0) == strlen(res)) &&
    getword(blob:res, pos:4) == seq &&
    getdword(blob:res, pos:8) == -1 &&
    getbyte(blob:res, pos:16) == 3
  ) 
  {
    report = string(
      "Nessus was able to gain access using the following credentials :\n",
      "\n",
      "  User Name : ", user, "\n",
      "  Password  : ", pass, "\n"
    );
    security_hole(port:port, extra:report);
  }
}


close(soc);
