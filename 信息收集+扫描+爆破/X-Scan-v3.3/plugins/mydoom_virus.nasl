#
# Copyright (C) 2004 Tenable Network Security
#
#
# rev 1.7: fixes a bug introduced in rev 1.6 spotted by Phil Bordelon 
# rev 1.6: MyDoom.B detection
#


include("compat.inc");

if(description)
{
 script_id(12029);
 script_version ("$Revision: 1.14 $");
 name["english"] = "MyDoom Virus Backdoor";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has a suspicious application installed." );
 script_set_attribute(attribute:"description", value:
"MyDoom backdoor is listening on this port. A cracker may connect to it
to retrieve secret information, e.g. passwords or credit card numbers." );
 script_set_attribute(attribute:"see_also", value:"http://securityresponse.symantec.com/avcenter/venc/data/w32.novarg.a@mm.html" );
 script_set_attribute(attribute:"see_also", value:"http://securityresponse.symantec.com/avcenter/venc/data/w32.mydoom.f@mm.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.math.org.il/newworm-digest1.txt" );
 script_set_attribute(attribute:"solution", value:
"Use an Anti-Virus package to remove it." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
 summary["english"] = "Detect MyDoom worm";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 family["english"] = "Backdoors";
 script_family(english:family["english"]);
 script_dependencie("os_fingerprint.nasl");
 exit(0);
}

include('global_settings.inc');

os = get_kb_item("Host/OS");
if ( os && "Windows" >!< os ) exit(0);


ports = make_list();
if ( thorough_tests )
{
 for ( port = 3127 ; port < 3198 ; port ++ ) 
 {
	ports = make_list(ports, port);
 }
}


ports = make_list(ports, 1080,80,3128,8080,10080);

foreach port (ports)
{
 if ( get_port_state(port) ) 
 {
	req = string("a");
	soc = open_sock_tcp(port);
	if ( soc ) 
	{
	send(socket:soc, data:req);
	r = recv(socket:soc, length:10, timeout:3);
	close(soc);
	if ( r && (strlen(r) == 8) && (ord(r[0]) == 4) ) security_hole(port); 
	}
 }
}

