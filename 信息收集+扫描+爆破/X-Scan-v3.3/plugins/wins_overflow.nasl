#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if(description)
{
 script_id(15912);
 script_version("$Revision: 1.12 $");

 script_cve_id("CVE-2003-0825");
 script_bugtraq_id(9624);
 script_xref(name:"OSVDB", value:"3903");

 script_name(english:"MS04-006: WINS Server Remote Overflow (830352) (uncredentialed check)");
 script_summary(english:"Determines if hotfix 830352 has been installed (Netbios)");
 
 script_set_attribute(
  attribute:"synopsis",
  value:"Arbitrary code can be executed on the remote host."
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote Windows Internet Naming Service (WINS) is affected by a\n",
   "vulnerability that could allow an attacker to execute arbitrary code\n",
   "on this host. \n",
   "\n",
   "To exploit this flaw, an attacker would need to send a specially\n",
   "crafted packet with improperly advertised lengths."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:"http://www.microsoft.com/technet/security/bulletin/MS04-006.mspx"
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");
 script_dependencies("netbios_name_get.nasl");
 script_require_ports(137);
 exit(0);
}

#

if ( get_kb_item("SMB/samba") ) exit(0);

port = 137;
soc = open_sock_udp(port);
if ( ! soc ) exit(0);


request = raw_string (0x83, 0x98, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		      0x3E, 0x46, 0x45, 0x45, 0x46, 0x45, 0x4f, 0x45, 0x42, 0x45, 0x43, 0x45,
                      0x4d, 0x45, 0x46 ) + crap (data:"A", length:48) +
		      crap (data:raw_string(0x3F), length:192) + 
		      raw_string (0x22) + crap (data:raw_string (0x3F), length:34) + 
                      raw_string ( 0x00, 0x00, 0x20, 0x00, 0x01); 

send(socket:soc, data:request);

r = recv(socket:soc, length:4096);
if (!r) exit (0);

r = substr (r, 13, 17);

if ("FEEFE" >< r)
  security_hole(port);

