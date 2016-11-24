#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10052);
 script_version ("$Revision: 1.33 $");
 script_cve_id("CVE-1999-0103");

 script_name(english:"Daytime Service Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"A daytime service is running on the remote host" );
 script_set_attribute(attribute:"description", value:
"The remote host is running a 'daytime' service.  This service is
designed to give the local time of the day of this host to whoever
connects to this port. 
 
The date format issued by this service may sometimes help an attacker
to guess the operating system type of this host, or to set up timed
authentication attacks against the remote host. 

In addition, if the daytime service is running on a UDP port, an
attacker may link it to the echo port of a third-party host using
spoofing, thus creating a possible denial of service condition between
this host and the third party." );
 script_set_attribute(attribute:"solution", value:
"- Under Unix systems, comment out the 'daytime' line in /etc/inetd.conf
  and restart the inetd process
 
- Under Windows systems, set the following registry keys to 0 :
  HKLM\System\CurrentControlSet\Services\SimpTCP\Parameters\EnableTcpDaytime
  HKLM\System\CurrentControlSet\Services\SimpTCP\Parameters\EnableUdpDaytime
   
Then launch cmd.exe and type :

   net stop simptcp
   net start simptcp
   
To restart the service." );
 script_set_attribute(attribute:"risk_factor", value:"None" );

script_end_attributes();

 script_summary(english:"Checks for the presence of daytime");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"Service detection");
 script_dependencie("find_service2.nasl");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");

port = get_kb_item("Services/daytime");
if (! port) port = 13;

if(get_port_state(port))
{
 k = 'FindService/tcp/'+port+'/spontaneous';
 a = get_kb_item(k);
 if (!a)
 {
  soc = open_sock_tcp(port);
  if(soc)
  {
   a = recv(socket:soc, length:1024);
   close(soc);
  }
  if (a) set_kb_item(name: k, value: a);
 }
 if(a) security_note(port);
}


if(get_udp_port_state(13))
{
 udpsoc = open_sock_udp(13);
 if ( ! udpsoc ) exit(0);
 data = '\n';
 send(socket:udpsoc, data:data);
 b = recv(socket:udpsoc, length:1024);
 register_service(port:13, proto:"daytime", ipproto:"udp");
 if(b)security_note(port:13, protocol:"udp");
 
 close(udpsoc);
}
