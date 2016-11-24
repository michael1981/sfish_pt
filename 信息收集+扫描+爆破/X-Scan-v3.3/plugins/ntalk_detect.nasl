#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25201);
  script_version("$Revision: 1.21 $");

  script_name(english: "ntalk Service Detection");
  script_summary(english: "Speaks to ntalkd (UDP)"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote service is a talk server (talkd)" );
 script_set_attribute(attribute:"description", value:
"The remote service answered to a ntalk request.

talkd is a server which notifies a user that someone else wants
to initiate a conversation. It works over UDP and is considered
by many to be obsolete today.

ntalk is implemented on UDP by the Unix command 'talk'." );
 script_set_attribute(attribute:"see_also", value:"The protocol is defined in <protocols/talkd.h>" );
 script_set_attribute(attribute:"solution", value:
"If you do not use this service, disable it." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english: "Service detection");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  exit(0);
}


# See protocols/talkd.h

include('network_func.inc');
include('misc_func.inc');
###include('dump.inc');

if ( TARGET_IS_IPV6 ) exit(0);

port = 518;
soc = open_sock_udp(port);
if (!soc) exit(0);

sport = get_source_port(soc);

v = split(this_host(), sep: '.', keep: 0);
addr = raw_string(int(v[0]), int(v[1]), int(v[2]), int(v[3]));

sp = htons(n: sport);

r = strcat(
	'\x01', 	# protocol version
	'\x01',		# request type: LOOK_UP
	'\0',		# Answer (unused)
	'\0',		# Pad
	'\0\0\0\0',	# Message id

	'\x00\x02',	# Family
	'\x00\x00',	# Port?
	addr, '\0\0\0\0\0\0\0\0',
	'\x00\x02',	# Family
	sp,	# Port?
	addr, '\0\0\0\0\0\0\0\0',
	'\x01\x02\x03\x04',	# Call ID process
	rand_str(length: 11), '\0',	# Caller's name
	rand_str(length: 11), '\0',	# Callee's name
	crap(data: '\0', length: 16)
	);

send(socket: soc, data: r);
r2 = recv(socket: soc, length: 1024);

##dump(dtitle: 'UDP', ddata: r2);

if (	strlen(r2) == 24 && 
	ord(r2[0]) == 1 &&	# Protocol version
	ord(r2[1]) >= 0 && ord(r2[1]) <= 8)	# Type (SUCCESS .. BADCTLADDR)
security_note(port: port, proto: 'udp');
