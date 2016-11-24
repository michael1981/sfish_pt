#
# (C) Tenable Network Security, Inc.
#

# routed from OpenBSD or Linux rejects routes that are not sent by a neighbour
# 
# The real test is done by rip_poison.nasl - this was split into two scripts
# as the CVSS scores are very different on a LAN and a WAN.

include("compat.inc");

if(description)
{
  script_id(39587);
  script_version ("$Revision: 1.2 $");

  script_name(english: "RIP Poisoning Routing Table Modification (Adjacent Network)");
  script_summary(english: "Poison routing tables through RIP (adjacent network)");
 
  script_set_attribute(attribute:"synopsis", value:
"Routing tables can be modified." );

  script_set_attribute(attribute:"description", value:
"It was possible to poison the remote host routing tables through the
RIP protocol. 

An attacker may use this to hijack network connections.

Several RIP agents reject routes that are not sent by a neighbor, so
this flaw may not be exploitable from a non-adjacent network.");
  script_set_attribute(attribute:"solution", value:
"Either disable the RIP listener if it is not used, use RIP-2 in
conjunction with authentication, or use another routing protocol." );
  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P" );
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_family(english: "Misc.");
  script_dependencie("rip_poison.nasl");
  script_require_keys("Services/udp/rip");
  exit(0);
}

if (! islocalnet()) exit(0);

port = get_kb_item("Services/udp/rip");
if (! port) port = 520;

if (get_kb_item('rip/'+port+'/poison'))
 security_warning(port: port, proto: "udp");
