#
# Copyright (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(14184);
 script_version ("$Revision: 1.2 $");
 script_name(english:"Zincite.A (MyDoom.M) Backdoor");
 script_summary(english:"Detect MyDoom worm");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote host may have been compromised by a worm."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The backdoor 'BackDoor.Zincite.A' is installed on the remote host.\n",
     "It has probably been installed by the 'MyDoom.M' virus.  This\n",
     "backdoor may allow an attacker to gain unauthorized access on the\n",
     "remote host."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://securityresponse.symantec.com/avcenter/venc/data/w32.mydoom.m@mm.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.microsoft.com/security/portal/Entry.aspx?name=Win32%2fMydoom"
 );
 script_set_attribute(
   attribute:"solution", 
   value:string(
     "Verify if the remote host has been compromised, and reinstall\n",
     "the system if necessary."
   )
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Backdoors");
 script_require_ports(1034);
 exit(0);
}


port = 1034;
if ( get_port_state(port) ) 
 {
	req = raw_string(0xc7);
	soc = open_sock_tcp(port);
	if ( soc ) 
	{
	send(socket:soc, data:req);
	r = recv(socket:soc, length:255, timeout:3);
        if ( raw_string(0x92, 0x3a, 0x6c) >< r && strlen(r) == 255 )	
	 security_hole(port);

	}
 }

