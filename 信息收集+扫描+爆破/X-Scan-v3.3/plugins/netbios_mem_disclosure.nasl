#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if(description)
{
 script_id(11830);
 script_version ("$Revision: 1.16 $");

 script_cve_id("CVE-2003-0661");
 script_bugtraq_id(8532);
 script_xref(name:"OSVDB", value:"2507");
 
 script_name(english:"MS03-034: Flaw in NetBIOS Could Lead to Information Disclosure (824105) (uncredentialed check)");
 script_summary(english:"Tests the NetBT NS mem disclosure");
 
 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "The remote service is affected by an information disclosure\n",
   "vulnerability."
  )
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote host is running a version of the NetBT name service that\n",
   "suffers from a memory disclosure problem.\n",
   "\n",
   "An attacker may send a special packet to the remote NetBT name\n",
   "service, and the reply will contain random arbitrary data from the\n",
   "remote host memory.  This arbitrary data may be a fragment from the\n",
   "web page the remote user is viewing, or something more serious like a\n",
   "password. \n",
   "\n",
   "An attacker may use this flaw to continuously 'poll' the content of\n",
   "the memory of the remote host and might be able to obtain sensitive\n",
   "information."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:"http://www.microsoft.com/technet/security/bulletin/ms03-034.mspx"
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
 );
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencie("netbios_name_get.nasl");
 script_require_keys("SMB/NetBIOS/137");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");

if (report_paranoia < 2) exit(0);

NETBIOS_LEN = 50;

sendata = raw_string(
rand()%255, rand()%255, 0x00, 0x00, 0x00,
0x01, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x20, 0x43, 0x4B,
0x41, 0x41, 0x41, 0x41, 0x41,
0x41, 0x41, 0x41, 0x41, 0x41,
0x41, 0x41, 0x41, 0x41, 0x41,
0x41, 0x41, 0x41, 0x41, 0x41,
0x41, 0x41, 0x41, 0x41, 0x41,
0x41, 0x41, 0x41, 0x41, 0x41,
0x00, 0x00, 0x21, 0x00, 0x01
			);


if(!(get_udp_port_state(137))){
	exit(0);
	}
	
soc = open_sock_udp(137);
send(socket:soc, data:sendata, length:NETBIOS_LEN);

result = recv(socket:soc, length:4096);
if(strlen(result) > 58)
{
 pad = hexstr(substr(result, strlen(result) - 58, strlen(result)));
 close(soc);
 
 sleep(1);
 
 soc2 = open_sock_udp(137);
 if(!soc2)exit(0);
 send(socket:soc2, data:sendata, length:NETBIOS_LEN);
 result = recv(socket:soc2, length:4096);
 if(strlen(result) > 58)
 {
  pad2 = hexstr(substr(result, strlen(result) - 58, strlen(result)));
  if(pad != pad2)security_warning(port:137, proto:"udp");
 }
}
