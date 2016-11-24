#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(35373);
 script_version("$Revision: 1.5 $");

 script_name(english:"DNS Server DNSSEC Aware Resolver");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote DNS resolver is DNSSEC-aware." );
 script_set_attribute(attribute:"description", value:
"The remote DNS resolver accepts DNSSEC options.  This means that it
may verify the authenticity of DNSSEC protected zones if it is
configured to trust their keys." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
script_end_attributes();


 script_summary(english: "Sends a DNSSEC query");
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "DNS");
 script_dependencies("dns_server.nasl");
 script_require_keys("DNS/udp/53");
 exit(0);
}

#

include("misc_func.inc");
include("dns_func.inc");
include("byte_func.inc");

function dnssec_query_A(a)
{
  local_var	pkt;

  pkt = raw_string(
      rand() % 256, rand() % 256,	# Transaction ID
      0x01, 0x00,			# Flags: standard query
      0, 1,				# Questions: 1
      0, 0,				# Answer RRs: 0
      0, 0,				# Authority RRs : 1
      0, 1);				# additional RRs: 1
  pkt += dns_str_to_query_txt(a);
  pkt += raw_string(
      0, 1,		# A
      0, 1,		# IN
      # Additional records
      0,		# Name: <Root>
      0, 0x29,		# Type: OPT (EDNS0 option)
      0x10, 0,		# UDP payload size: 4096
      0,
      0,		# EDNS0 version: 0
      0x80, 0,		# Accept DNSSEC security RRs
      0, 0);		# Data length: 0
  return pkt;
}

if (! COMMAND_LINE && ! get_kb_item("DNS/udp/53")) exit(0);


soc = open_sock_udp(53);
if (! soc) exit(0);

pkt = dnssec_query_A(a: "www.example.com");
send(socket:soc, data: pkt);

r = recv(socket:soc, length: 8192);
if(strlen(r) > 3)
{
  if ( (ord(r[2]) & 0xF8) == 0x80 &&	# Response + std query
       (ord(r[3]) & 0x0F) == 0  )	# No error
  {
    ques_nb = 256 * ord(r[4]) + ord(r[5]);
    answ_nb = 256 * ord(r[6]) + ord(r[7]);
    auth_nb = 256 * ord(r[8]) + ord(r[9]);
    addi_nb = 256 * ord(r[10]) + ord(r[11]);
    p = 12;
    for (i = 0; i < ques_nb; i ++)
    {
      # Skip name
      while (ord(r[p]) != 0)
      {
        p += ord(r[p]) + 1;
      }
      p ++;
      p += 4;
    }
    for (i = 0; i < answ_nb + auth_nb + addi_nb; i ++)
    {
      if (isnull(r[p])) break;
      if ( ord(r[p]) == 0 &&	# Root
           ord(r[p+1]) == 0 && ord(r[p+2]) == 0x29 &&	# OPT
	   (ord(r[p+7]) & 0x80) == 0x80)
      {
	security_note(port: 53, proto: "udp");
	set_kb_item(name: "DNSSEC/udp/53", value: TRUE);
	break;
      }
      if ((ord(r[p]) & 0xC0) == 0xC0)	# Compression
      {
        p += 2;
      }
      else
      {
        while (ord(r[p]) != 0)
	{
          p += ord(r[p]) + 1;
        }
	p ++;
      }
      p += 2 + 2 + 4;	# Type & class & TTL
      datalen = ord(r[p]) * 256 + ord(r[p+1]);
      p += datalen + 2;
    }
  }
}
 
close(soc);
