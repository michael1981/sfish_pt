#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10196);
 script_version ("$Revision: 1.24 $");
 script_cve_id("CVE-1999-0006");
 script_bugtraq_id(133);
 script_xref(name:"OSVDB", value:"912");

 script_name(english:"Qpopper PASS Command Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote server." );
 script_set_attribute(attribute:"description", value:
"There is a bug in some versions of Qpopper which allows a remote user
to become root using a buffer overflow." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of Qpopper." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 script_summary(english: "Qpopper buffer overflow");
 
 script_category(ACT_MIXED_ATTACK); # mixed
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_dependencie("popserver_detect.nasl");
 script_require_ports("Services/pop3", 110);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");

port = get_kb_item("Services/pop3");
if(!port)port = 110;
if (! get_port_state(port)) exit(0);

if(safe_checks())
{
 banner = get_kb_item(string("pop3/banner/", port));
 if (! banner && thorough_tests)
 {
  soc = open_sock_tcp(port);
  if(!soc)exit(0);
  banner = recv_line(socket:soc, length:4096);
  
  if("QPOP" >< banner)
  {
   if(ereg(pattern:".*version (1\..*)|(2\.[0-4])\).*",
   	   string:banner))
	   {
	    security_hole(port:port);
	   }
  }
 }
 exit(0);
}

if (report_paranoia < 2) exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);
buf = recv_line(socket:soc, length:4095);
if(!strlen(buf)){
	set_kb_item(name:"pop3/false_pop3", value:TRUE);
 	close(soc);
	exit(0);
	}
if ( "QPOP" >!< buf )
{
 close(soc);
 exit(0);
}

command = string(crap(4095), "\r\n", buf);
send(socket:soc, data:command);
buf2 = recv_line(socket:soc, length:5000);
buf3 = recv_line(socket:soc, length:4095);

send(socket:soc, data: 'QUIT\r\n');
r = recv(socket:soc, length:4096);
len = strlen(r);
if(!len)
{
 security_hole(port);
}
close(soc);

