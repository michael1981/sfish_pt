#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11168);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2002-1318");
 script_bugtraq_id(6210);
 script_xref(name:"OSVDB", value:"14525");

 script_name(english: "Samba Encrypted Password String Conversion Decryption Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"Remote code can be executed on the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote Samba server, according to its version number, is vulnerable
to a bug in the length checking for encrypted password change requests 
from clients. A client could potentially send an encrypted password, 
which, when decrypted with the old hashed password could be used as a
buffer overrun attack on the stack of smbd." );
 script_set_attribute(attribute:"solution", value:
"upgrade to Samba 2.2.7" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();
 
 script_summary(english: "checks samba version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english: "Gain a shell remotely");
 script_dependencie("smb_nativelanman.nasl");
 script_require_ports(139);
 script_require_keys("SMB/NativeLanManager");
 exit(0);
}

#
# The script code starts here
#

lanman = get_kb_item("SMB/NativeLanManager");
if("Samba" >< lanman)
{
 # Samba 2.2.2 to 2.2.6 is affected
 if(ereg(pattern:"Samba 2\.2\.[2-6][^0-9]*$",
 	 string:lanman))security_hole(139);
}
