#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10028);
 script_version ("$Revision: 1.43 $");
 script_xref(name:"OSVDB", value:"23");

 script_name(english:"ISC BIND version Directive Remote Version Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the version number of the remote DNS server." );
 script_set_attribute(attribute:"description", value:
"The remote host is running BIND, an open-source DNS server.  It is
possible to extract the version number of the remote installation by
sending a special DNS request for the text 'version.bind' in the
domain 'chaos'." );
 script_set_attribute(attribute:"solution", value:
"It is possible to hide the version number of bind by using the
'version' directive in the 'options' section in named.conf" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_end_attributes();
 
 script_summary(english:"Sends a VERSION.BIND request");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english: "DNS");
 script_dependencies("dns_server.nasl");
 script_require_keys("DNS/udp/53");
 exit(0);
}


include("dns_func.inc");
include("byte_func.inc");


if ( get_kb_item("DNS/udp/53") )
{
 dns["transaction_id"] = rand() & 0xffff;
 dns["flags"]	      = 0x0010;
 dns["q"]	      = 1;
 packet = mkdns(dns:dns, query:mk_query(txt:mk_query_txt("VERSION", "BIND"),type:0x0010, class:0x0003));
 soc = open_sock_udp(53);
 send(socket:soc, data:packet);
 r = recv(socket:soc, length:4096);
 close(soc);
 response  = dns_split(r);
 if ( isnull(response) ) exit(0);
 f = response["flags"];
 
 if (f  & 0x8000 && !( f & 0x0003 ) && ! isnull( get_query_txt(response["an_rr_data_0_data"]) ) ) 
 {
  version = get_query_txt(response["an_rr_data_0_data"]);
  set_kb_item(name:"bind/version", value:version);
  report = '\nThe version of the remote DNS server is :\n\n' + get_query_txt(response["an_rr_data_0_data"]);
  
  # NSD will also respond to VERSION.BIND requests. make sure this isn't NSD.
  if (!ereg(string:version, pattern:"^NSD [0-9.]+$", icase:TRUE))
    security_note(port:53, proto: "udp", extra:report);
 }
}
