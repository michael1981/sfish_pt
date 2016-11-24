# Written by Michel Arboi <mikhail@nessus.org>
# I'm not sure what this backdoor is...
#


include("compat.inc");

if(description)
{
 script_id(18392);
 script_version ("$Revision: 1.6 $");
 script_set_attribute(attribute:"synopsis", value:
"The remote host has been compromised." );
 script_set_attribute(attribute:"description", value:
"This host seems to be running an ident server, but before any 
request is sent, the server gives an answer about a connection 
to port 6667.

It is very likely this system has been compromised by an IRC 
bot and is now a 'zombie' that can participate in 'distributed 
denial of service' (DDoS) attacks." );
 script_set_attribute(attribute:"solution", value:
"Disinfect or re-install your system." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

 script_name(english: "IRC Bot Detection");
script_end_attributes();

 script_summary(english: "Fake IDENT server (IRC bot)");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english: "Backdoors");
 script_require_ports("Services/fake-identd", 113);
 script_dependencies("find_service1.nasl");
 exit(0);
}

#

# include('misc_func.inc');

regex = '^[0-9]+ *, *6667 *: *USERID *: *UNIX *: *[A-Za-z0-9]+';

port = get_kb_item('Services/fake-identd');
if (! port) port = 113;

if (! get_port_state(port)) exit(0);

b = get_kb_item('FindService/tcp/'+port+'/spontaneous');
# if (! b) b = get_unknown_banner(port: port);
if (! b) exit(0);

if (b =~ '^[0-9]+ *, *6667 *: *USERID *: *UNIX *: *[A-Za-z0-9]+')
{
  security_hole(port);
  set_kb_item(name: 'backdoor/TCP/'+port, value: TRUE);
}
