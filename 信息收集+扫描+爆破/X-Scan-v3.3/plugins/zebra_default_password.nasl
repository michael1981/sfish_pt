#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
 script_id(16205);
 script_version ("$Revision: 1.7 $");

 script_bugtraq_id(10935);
 script_xref(name:"OSVDB", value:"9074");
 
 script_name(english:"Default Password (zebra) for Zebra");
	     
 script_set_attribute(
  attribute:"synopsis",
  value:"The remote router is protected with a default password."
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote host is running Zebra, a routing daemon.\n",
   "\n",
   "The remote Zebra installation uses as its password the default,\n",
   "'zebra'.  An attacker may log in using this password and control the\n",
   "routing tables of the remote host."
  )
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://archives.neohapsis.com/archives/bugtraq/2004-08/0181.html"
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://archives.neohapsis.com/archives/bugtraq/2004-08/0201.html"
 );
 script_set_attribute(
  attribute:"solution", 
  value:"Edit 'zebra.conf' and set a strong password."
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();
		 
 script_summary(english:"Logs into the remote host");

 script_category(ACT_GATHER_INFO);

 script_family(english:"Firewalls");
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 
 script_dependencie("find_service2.nasl");
 script_require_ports("Services/zebra", 2601);
 exit(0);
}


include('telnet_func.inc');

port = get_kb_item("Services/zebra");
if ( ! port ) port = 2601;
if ( ! get_port_state(port) ) exit(0);


soc = open_sock_tcp(port);
if(!soc)return(0);

res = telnet_negotiate(socket:soc);
res += recv_until(socket:soc, pattern:"Password: ");
if ( ! res ) exit(0);

send(socket:soc, data:'zebra\r\n'); # Default password
res = recv_until(socket:soc, pattern:"> "); # Wait for the cmd prompt
send(socket:soc, data:'list\r\n'); # Issue a 'list' command
res = recv(socket:soc, length:4096);
if ( "show memory" >< res )
	security_hole(port);
