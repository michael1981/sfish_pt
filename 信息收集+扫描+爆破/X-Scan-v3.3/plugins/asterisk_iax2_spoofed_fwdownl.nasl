#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33564);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2008-3264");
  script_bugtraq_id(30350);
  script_xref(name:"Secunia", value:"31178");
  script_xref(name:"OSVDB", value:"47254");

  script_name(english:"Asterisk IAX2 FWDOWNL Request Spoofing Remote DoS");
  script_summary(english:"Sends an FWDOWNL request");

 script_set_attribute(attribute:"synopsis", value:
"The remote VoIP service can be abused to conduct an amplification
attack against third-party hosts." );
 script_set_attribute(attribute:"description", value:
"The firmware download protocol implemented in the version of Asterisk
installed on the remote host does not initiate a handshake.  By
spoofing an IAX2 FWDOWNL request, an unauthenticated remote attacker
may be able to leverage this issue to flood a third-party host with
unwanted firmware packets from the affected host." );
 script_set_attribute(attribute:"see_also", value:"http://downloads.digium.com/pub/security/AST-2008-011.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/494676/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Asterisk Open Source 1.4.21.2 / 1.2.30, Asterisk Business
Edition C.2.0.3 / C.1.10.3 / B.2.5.4, s800i (Asterisk Appliance)
1.2.0.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("iax2_detection.nasl");
  script_require_keys("Services/udp/iax2");

  exit(0);
}


include("byte_func.inc");


port = get_kb_item("Services/udp/iax2");
if (!port) port = 4569;


soc = open_sock_udp(port);


# Send a FWDOWNL request.
src_call = rand() % 0xff;
firmware = "iaxy";

req =
  mkword((1 << 15) | src_call) +       # 'F' bit + source call number
  mkword(0) +                          # 'R' bit + dest call number
  mkdword(0) +                         # timestamp
  mkbyte(0) +                          # OSeqno
  mkbyte(0) +                          # ISeqno
  mkbyte(6) +                          # frametype, 6 => IAX frame
  mkbyte(0x24) +                       # 'C' bit + subclass, 0x24 => FWDOWNL request
                                       #   information elements
    mkbyte(0x20) +                     #     DEVICETYPE
      mkbyte(strlen(firmware)) +
      firmware +
    mkbyte(0x23) +                     #     FWBLOCKDESC
      mkbyte(0x04) +
      mkdword(2);
send(socket:soc, data:req);
res = recv(socket:soc, length:128);
if (strlen(res) == 0) exit(0);


# There's a problem if we get an FWDATA response.
if (
  getword(blob:res, pos:0) > 0x8000 &&
  getword(blob:res, pos:2) & 0x7fff == src_call &&
  getbyte(blob:res, pos:10) == 6 &&
  getbyte(blob:res, pos:11) == 0x25
) security_warning(port);
