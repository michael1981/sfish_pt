#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11211);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2003-1354");
 script_bugtraq_id(6636);
 script_xref(name:"OSVDB", value:"51819");
 
 script_name(english:"GameSpy 3D Based Games Spoofed UDP Response Amplification DDoS");

 script_set_attribute(attribute:"synopsis", value:
"A game server is running on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a GameSpy server.  This service is used to
host a gaming server. 

Since it uses UDP as its transport layer and sends multiple UDP packets
in response to one request, an attacker can abuse it to flood a
third-party host with traffic by sending a spoofed UDP packet with the
IP address of their target as the source field." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d9bb249" );
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port or disable the service." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
script_end_attributes();

 
 script_summary(english:"Checks for the presence of a GameSpy server");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Denial of Service");
 script_require_keys("Settings/ThoroughTests");
 exit(0);
}

# There's <official port> to bind a gamespy server to, and
# scanning all the UDP ports would take too much time. We try
# a list of common ports instead.
include('global_settings.inc');
if ( ! thorough_tests ) exit(0);

port[0] = 7777;
port[1] = 8888;
port[2] = 12203;
port[3] = 12204;
port[4] = 14567;
port[5] = 14570;
port[6] = 22000;
port[7] = 23000;
port[8] = 27015;
port[9] = 27016;
port[10] = 27960;
port[11] = 27961;
port[12] = 28001;
port[13] = 28002;
port[14] = 28016;
port[15] = 28020;
port[16] = 28040;
port[17] = 28672;

port[18] = 0;

for(i=0;port[i];i=i+1)
{
soc = open_sock_udp(port[i]);
if ( ! soc ) exit(0);
send(socket:soc, data:string("\\players\\rules\\status\\packets\\"));
r = recv(socket:soc, length:4096, timeout:2);
if(strlen(r) > 0)
 {
 if(("disconnect" >< r) ||
    (strlen(r) == 4 && ord(r[0]) == 0x00 && ord(r[1]) == 0x40))
    	{
	set_kb_item(name:"Services/udp/gamespy", value:port[i]);
	security_warning(port[i]);
	exit(0);
	}
 }
 close(soc);
}
