#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10068);
 script_version ("$Revision: 1.31 $");
 script_cve_id("CVE-1999-0612");
 script_xref(name:"OSVDB", value:"11451");

 script_name(english:"Finger Service Remote Information Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain information about the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the 'finger' service. 

The purpose of this service is to show who is currently logged into
the remote system, and to give information about the users of the
remote system. 
 
It provides useful information to attackers, since it allows them to
gain usernames, determine how used a machine is, and see when each
user logged in for the last time." );
 script_set_attribute(attribute:"solution", value:
"Comment out the 'finger' line in /etc/inetd.conf and restart the 
inetd process" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );


script_end_attributes();

 script_summary(english:"Checks for finger");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 script_family(english:"Finger abuses");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/finger", 79);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/finger");
if(!port)port = 79;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  buf = string("root\r\n");
  send(socket:soc, data:buf);
  data = recv(socket:soc, length:65535);
  if(egrep(pattern:".*User|[lL]ogin|logged.*", string:data))
  {
   report = 'Here is the output we obtained for \'root\' : \n\n' + data + '\n';

   security_warning(port:port, extra:report);
   set_kb_item(name:"finger/active", value:TRUE);
  }

  close(soc);
 }
}
