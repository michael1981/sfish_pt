#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
	script_id(10151);
	script_version ("$Revision: 1.24 $");

	script_cve_id("CVE-2003-1475");
	script_bugtraq_id(7538);
	script_xref(name:"OSVDB", value:"20");
	script_xref(name:"OSVDB", value:"59637");

	script_name(english:"NetBus 1.x Detection");
	script_summary(english:"Checks for the presence of NetBus 1.x");

	script_set_attribute(
    attribute:'synopsis',
    value:'A potentially malicious remote administration service is detected.'
  );

  script_set_attribute(
    attribute:'description',
    value:
"NetBus 1.x is installed.

NetBus is a remote administration tool that can be used for malicious
purposes, such as sniffing what the user is typing, its passwords and
so on. 

An attacker may have installed it to control hosts on your network. 

Furthermore, Netbus authentication may be bypassed."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Netbus should be removed from the system."
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.securityfocus.com/archive/1/320980'
	);

  script_set_attribute(
    attribute:'see_also',
    value:'http://members.spree.com/NetBus/remove_1.html'
  );

  script_set_attribute(
    attribute:'see_also',
    value: "http://members.spree.com/NetBus/remove_2.html"
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P'
  );

  script_end_attributes();

 	script_category(ACT_GATHER_INFO);

	script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
	script_family(english:"Backdoors");
	script_dependencie("find_service1.nasl");
	script_require_ports(12345, "Services/netbus");
	exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/netbus");
if(!port)port = 12345;

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {

#
# Anti-deception toolkit check
#
  r = recv(socket:soc, length:1024);
  close(soc);
  if("NetBus" >< r){
  	security_hole(port);
	}
  }
}
