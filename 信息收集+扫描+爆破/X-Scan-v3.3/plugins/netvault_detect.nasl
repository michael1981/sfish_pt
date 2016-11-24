#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25800);
  script_version("$Revision: 1.4 $");

  script_name(english:"NetVault Process Manager Service Detection");
  script_summary(english:"Tries to detect NetVault Process Manager");

 script_set_attribute(attribute:"synopsis", value:
"A backup service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service is an instance of NetVault Process Manager, part of
BakBone NetVault Backup, a cross-platform backup and restore
application." );
 script_set_attribute(attribute:"see_also", value:"http://www.bakbone.com/products/backup_and_restore/" );
 script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 20031);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") )
{
  port = get_unknown_svc(20031);
  if (!port) exit(0);
}
else port = 20031;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);


# Send a request.
req = raw_string(0x01, 0xcb, 0x22, 0x77, 0xc9) +
    mkdword(0x17) +
      crap(data:"i;", length:0x14) + "s;" + mkbyte(0) + 
    mkdword(0) + 
    mkdword(0xc0) + 
    mkdword(0) +
    mkdword(0) +
    mkdword(0) +
    mkdword(0) +
    mkdword(8) + 
    mkdword(3) + 
    mkdword(3) + 
    mkdword(0) + 
    mkdword(0x0b) +
      crap(data:raw_string(0x90), length:0x0a) +
    crap(data:raw_string(0x00), length:0x66) +
    mkbyte(9) + 
      crap(data:raw_string(0x00), length:8);
req = mkdword(strlen(req)+4) + req;
send(socket:soc, data:req);
res = recv(socket:soc, length:1024);
close(soc);


# If...
if (
  # the initial dword is the packet length and...
  strlen(res) > 4 && getdword(blob:res, pos:0) == strlen(res) &&
  # and it looks like a valid response
  substr(res, 4, 9) == substr(req, 4, 9)
)
{
  # Extract some interesting info for the report.
  info = "";
  nvver = NULL;
  nvbuild = NULL;
  # - machine name.
  len = getdword(blob:res, pos:0x4c);
  if (len > 0 && len < strlen(res))
  {
    cname = substr(res, 0x50, 0x50+len-2);
    info += "  Machine name  : " + cname + '\n';
  }
  # - computer os type.
  i = stridx(res, mkdword(5)+"Type"+'\0');
  if (i > 0)
  {
    i += 17;
    len = getdword(blob:res, pos:i);
    info += "  Computer type : " + substr(res, i+4, i+4+len-2) + '\n';
  }
  # - installation type
  i = stridx(res, mkdword(7)+"Server"+'\0');
  if (i > 0)
  {
    i += 19;
    len = getdword(blob:res, pos:i);
    word = substr(res, i+4, i+4+len-2);
    if (word =~ "true") 
    {
      info += "  Installation  : " + "Server" + '\n';
      set_kb_item(name:"NetVault/"+port+"/Type", value:"Server");
    }
    else if (word =~ "false") 
    {
      info += "  Installation  : " + "Client" + '\n';
      set_kb_item(name:"NetVault/"+port+"/Type", value:"Client");
    }
  }
  # - NetVault version.
  i = stridx(res, mkdword(0x0a)+"NVVersion"+'\0');
  if (i > 0)
  {
    i += 22;
    len = getdword(blob:res, pos:i);
    nvver = substr(res, i+4, i+4+len-2);
  }
  i = stridx(res, mkdword(0x0d)+"NVBuildLevel"+'\0');
  if (i > 0)
  {
    i += 25;
    len = getdword(blob:res, pos:i);
    nvbuild = substr(res, i+4, i+4+len-2);
  }
  if (
    !isnull(nvver) && nvver =~ "^[0-9]0[0-9][0-9]$" &&
    !isnull(nvbuild) && nvbuild =~ "^[0-9]+$"
  )
  {
    set_kb_item(name:"NetVault/"+port+"/NVVersion", value:nvver);
    set_kb_item(name:"NetVault/"+port+"/NVBuild", value:nvbuild);

    ver = string(nvver[0], ".", nvver[2], nvver[3], " Build ", nvbuild);
    info += "  Version       : " + ver + '\n';
  }

  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"nvpmgr");

  if (info)
    report = string(
      "Nessus was able to gather the following information from the remote\n",
      "NetVault Process Manager instance :\n",
      "\n",
      info
    );
  else report = NULL;
  security_note(port:port, extra:report);
}
