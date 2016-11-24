#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33576);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2008-3263");
  script_bugtraq_id(30321);
  script_xref(name:"Secunia", value:"31178");
  script_xref(name:"OSVDB", value:"47253");

  script_name(english:"Asterisk IAX2 (IAX) POKE Request Saturation Resource Exhaustion Remote DoS");
  script_summary(english:"Sends a POKE and examines src callno in the PONG");

 script_set_attribute(attribute:"synopsis", value:
"The remote VoIP service is susceptible to a remote denial of service
attack." );
 script_set_attribute(attribute:"description", value:
"The version of Asterisk installed on the remote host consumes an IAX2
call number while waiting for an ACK packet in response to a PONG
packet.  By flooding the affected service with POKE requests, an
unauthenticated remote attacker can leverage this issue to exhaust all
available call numbers and prevent legitimate IAX2 calls from getting
through." );
 script_set_attribute(attribute:"see_also", value:"http://downloads.digium.com/pub/security/AST-2008-010.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/494675/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Asterisk Open Source 1.4.21.2 / 1.2.30, Asterisk Business
Edition C.2.0.3 / C.1.10.3 / B.2.5.4, s800i (Asterisk Appliance)
1.2.0.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("iax2_detection.nasl");
  script_require_keys("Services/udp/iax2");

  exit(0);
}


include("byte_func.inc");


port = get_kb_item("Services/udp/iax2");
if (!port) port = 4569;


for (iter=0; iter<2; iter++)
{
  soc = open_sock_udp(port);

  # Send a POKE.
  src_call = rand() % 0xff;

  poke = 
    mkword((1 << 15) | src_call) +     # 'F' bit + source call number
    mkword(0) +                        # 'R' bit + dest call number
    mkdword(0) +                       # timestamp
    mkbyte(0) +                        # OSeqno
    mkbyte(0) +                        # ISeqno
    mkbyte(6) +                        # frametype, 6 => IAX frame
    mkbyte(0x1e);                      # 'C' bit + subclass, 0x1e => POKE request
  send(socket:soc, data:poke);
  pong = recv(socket:soc, length:128);
  if (strlen(pong) == 0) exit(0);

  # If we get a PONG...
  if (
    getword(blob:pong, pos:0) > 0x8000 &&
    getword(blob:pong, pos:2) & 0x7fff == src_call &&
    getbyte(blob:pong, pos:10) == 6 &&
    getbyte(blob:pong, pos:11) == 3
  )
  {
    # Send an ACK so the call number doesn't remain allocated.
    callid = getword(blob:pong, pos:0) ^ 0x8000;
    seqo = getbyte(blob:pong, pos:8);
    seqi = getbyte(blob:pong, pos:9);
    ts = getdword(blob:pong, pos:4);

    ack =
      mkword((1 << 15) | src_call) +   # 'F' bit + source call number
      mkword(callid) +                 # 'R' bit + dest call number
      mkdword(ts) +                    # timestamp
      mkbyte(seqo) +                   # OSeqno
      mkbyte(seqi) +                   # ISeqno
      mkbyte(6) +                      # frametype, 6 => IAX frame
      mkbyte(4);                       # 'C' bit + subclass, 4 => ACK
    send(socket:soc, data:ack);

    # There's a problem if the source call id is not 1.
    if (callid != 1)
    {
      security_warning(port);
      exit(0);
    }
  }
  # Exit because it doesn't seem to support IAX2.
  else exit(0);
}
