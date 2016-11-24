#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10094);
 script_version ("$Revision: 1.22 $");

 script_xref(name:"OSVDB", value:"20");

 script_name(english:"GirlFriend Backdoor Detection");
 script_summary(english:"Checks for the presence of Girlfriend");
 script_set_attribute(attribute:"synopsis", value:
"The remote host has a backdoor installed." );
 script_set_attribute(attribute:"description", value:
"The remote host has the GirlFriend backdoor installed. This backdoor
allows anyone to partially take control of the remote system. An
attacker could use it to steal your password or prevent your system
from working properly." );
 script_set_attribute(attribute:"solution", value:
"Open regedit to HKLM\Software\Microsoft\Windows\CurrentVersion\Run and
look for a value named 'Windll.exe' with the data
'c:\windows\windll.exe'. Reboot to DOS and delete the
'c:\windows\windll.exe' file then boot to Windows and remove the
'Windll.exe' registry value." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 family["english"] = "Backdoors";
 script_family(english:family["english"]);
 script_dependencie("find_service1.nasl");
 script_require_ports(21554,21544);
 script_require_keys("Settings/ThoroughTests");
 exit(0);
}

#
# The script code starts here
#

include('global_settings.inc');

if ( ! thorough_tests ) exit(0);

#1.0 beta
port = 21554;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  send(socket:soc, data:"ver", 3);
  a = recv_line(socket:soc, length:20);
  if("GirlFriend" >< a)security_hole(port);
  close(soc);
 }
}

#1.3 and 1.35
port = 21544;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  send(socket:soc, data:"ver", 3);
  a = recv_line(socket:soc, length:20);
  if("GirlFriend" >< a)security_hole(port);
  close(soc);
 }
}
