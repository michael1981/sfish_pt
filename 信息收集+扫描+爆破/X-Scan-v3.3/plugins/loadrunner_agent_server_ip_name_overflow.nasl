#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(24327);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2007-0446");
  script_bugtraq_id(22487);
  script_xref(name:"OSVDB", value:"33132");

  script_name(english:"Mercury LoadRunner Agent server_ip_name Field Remote Buffer Overflow");
  script_summary(english:"Sends an invalid request to a LoadRunner agent");

 script_set_attribute(attribute:"synopsis", value:
"The remote server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of the LoadRunner Agent installed on the remote host
contains a buffer overflow in 'mchan.dll' that can be exploited by an
unauthenticated remote attacker using a request with a long
'server_ip_name' field to crash the affected service or execute
arbitrary code subject to the permissions of the user id under which
the agent runs." );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-07-007.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2007-02/0177.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/459496" );
 script_set_attribute(attribute:"solution", value:
"HP no longer supports version 8.x of this product and patches may
no longer be available. HP recommends all users upgrade to latest
available version of 9.x." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_dependencies("loadrunner_agent_detect.nasl");
  script_require_ports("Services/loadrunner_agent");

  exit(0);
}


include("byte_func.inc");
include("misc_func.inc");


port = get_kb_item("Services/loadrunner_agent");
if (!port) exit(0);
if (!get_port_state(port)) exit(0);


# Establish a connection.
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
# nb: don't change these!!!
server_name = "nessus";
server_full_name = server_name;
server_ip = server_name;
server_port = 12345;


# Send an invalid request.
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
          "(-guid_identifier=", guid, ")",
          # nb: crap length is chosen so that the length of the subpacket
          #     is 0x400, which in a patched version will cause the
          #     thread to just close.
          "(-crap=", crap(data:"A", length:0x34a), ")"
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


# There's a problem if we see a response.
res = recv(socket:soc, length:4);
if (strlen(res) == 4 && getdword(blob:res, pos:0) == 0x1c) security_hole(port);


close(soc);
