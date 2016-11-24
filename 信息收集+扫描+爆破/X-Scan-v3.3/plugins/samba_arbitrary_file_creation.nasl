#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10786);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2001-1162");
 script_bugtraq_id(2928);
 script_xref(name:"OSVDB", value:"656");

 script_name(english: "Samba NETBIOS Name Traversal Arbitrary Remote File Creation");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary files may be overwritten on the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote Samba server, according to its version number, allows
creation of arbitrary remote files. 

This vulnerability allows an attacker to overwrite arbitrary files by
supplying an arbitrarily formed NetBIOS machine name to this server,
and to potentially become root on the remote server. 

An attacker does not need any privileges to exploit this flaw." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Samba 2.0.10 or 2.2.0a" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
 script_end_attributes();

 script_summary(english: "checks samba version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english: "Gain a shell remotely");
 script_dependencie("smb_nativelanman.nasl");
 script_require_keys("SMB/NativeLanManager");
 exit(0);
}

#
# The script code starts here
#

lanman = get_kb_item("SMB/NativeLanManager");
if("Samba" >< lanman)
{
 if(ereg(pattern:"Samba 2\.0\.[5-9][^0-9]*$",
 	 string:lanman))security_hole(139);
	 
 if(ereg(pattern:"Samba 2\.2\.0$", string:lanman))security_hole(139);
}
