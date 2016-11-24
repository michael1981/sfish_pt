#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10152);
  script_version ("$Revision: 1.25 $");

  script_xref(name:"OSVDB", value:"20");

  script_name(english:"NetBus 2.x Detection");
  script_summary(english:"Determines the presence of NetBus Pro");

	script_set_attribute(
    attribute:'synopsis',
    value:'A potentially malicious remote administration service is detected.'
  );

  script_set_attribute(
    attribute:'description',
    value:"NetBus 2.x is installed.

NetBus is a remote administration tool that can be used for malicious purposes, such as sniffing
what the user is typing, its passwords and so on.

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
  script_dependencie("os_fingerprint.nasl");
  script_require_ports(20034);
  exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");

if (report_paranoia < 2) exit(0);

os = get_kb_item("Host/OS");
if(os)
{
 if("Windows" >!< os)exit(0);
}

#
# Reverse-engineered data. Not very meaningful.
# Thanks to Jean Marc Herraud <herraud@rennes.enst-bretagne.fr>
#

s = raw_string(0x42, 0x4e, 0x1f, 0x00, 0x02, 0x00, 0xdc, 0x33,
               0x05, 0x00, 0x41, 0x0c, 0x69, 0x1f, 0x5d, 0x28,
	       0x5b, 0x95, 0x9c, 0xad, 0x95, 0xa8, 0xe6, 0x28 ,
	       0xfd ,0x1d, 0xfa, 0x10, 0x55, 0x83, 0xe2);

r = raw_string(0x42, 0x4e, 0x10, 0x00, 0x02, 0x00);

if(get_port_state(20034))
{
 soc = open_sock_tcp(20034);
 if(soc)
 {
 send(socket:soc, data:s, length:31);
 r2 = recv(socket:soc, length:6);
 if(r2){
   	flag = 0;
 	for(i=0;i<6;i=i+1)
	{
	 if(!(r[i]==r2[i])){
	 	flag = flag + 1;
		exit(0);
		}
	}
	if(!flag)security_hole(20034);
      }
 close(soc);
 }
}
