#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(19999);
 script_version("$Revision: 1.14 $");
 script_bugtraq_id(15066);
 script_cve_id("CVE-2005-1985");
 script_xref(name:"OSVDB", value:"19922");

 name["english"] = "MS05-046: Vulnerability in the Client Service for NetWare Could Allow Remote Code Execution (899589)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"A flaw in the client service for NetWare may allow an attacker to execute
arbitrary code on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Client Service for NetWare which 
is vulnerable to a buffer overflow.

An attacker may exploit this flaw by connecting to the NetWare RPC service
(possibly over IP) and trigger the overflow by sending a malformed RPC
request." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-046.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );



script_end_attributes();

 
 summary["english"] = "Determines the presence of update 899589";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


if ( hotfix_check_sp(xp:3, win2003:2, win2k:6) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, arch:"x86", file:"nwwks.dll", version:"5.2.3790.386", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, arch:"x86", file:"nwwks.dll", version:"5.2.3790.2506", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"nwwks.dll", version:"5.1.2600.1727", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"nwwks.dll", version:"5.1.2600.2736", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0",       file:"nwwks.dll", version:"5.0.2195.7065", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS05-046", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
