#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10024);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"1999-t-0002");
 script_version ("$Revision: 1.26 $");

 script_xref(name:"OSVDB", value:"20");
 script_name(english:"BackOrifice Software Detection");
 script_summary(english:"Determines the presence of BackOrifice");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has a backdoor program installed." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running BackOrifice 1.x with no password.
BackOrifice is a trojan which allows an intruder to take control of
the remote computer." );
 script_set_attribute(attribute:"solution", value:
"Remove BackOrifice from your computer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"Backdoors");
 script_dependencie("os_fingerprint.nasl");
 script_require_keys("Settings/ThoroughTests");
 exit(0);
}

#
# The script code starts here
#

include('global_settings.inc');

if ( ! thorough_tests ) exit(0);
os = get_kb_item("Host/OS");
if(os)
{
 if("Windows" >!< os)exit(0);
}

if(!(get_udp_port_state(31337)))exit(0);

#
# Reverse-engineered data. Not very meaningful.
# This is a 'ping' request for BackOrifice
#

s = raw_string(0xCE, 0x63, 0xD1, 0xD2, 0x16, 0xE7, 
	       0x13, 0xCF, 0x39, 0xA5, 0xA5, 0x86, 
	       0x4D, 0x8A, 0xB4, 0x66, 0xAA, 0x32);
	    
soc = open_sock_udp(31337);
send(socket:soc, data:s, length:18);
r = recv(socket:soc, length:10);
if(r)security_hole(31337);
close(soc);
