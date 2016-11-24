#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(25168);
 script_version("$Revision: 1.10 $");

 script_cve_id("CVE-2007-1748");
 script_bugtraq_id(23470);
 script_xref(name:"OSVDB", value:"34100");

 name["english"] = "MS07-029: Vulnerability in Windows DNS RPC Interface Could Allow Remote Code Execution (935966)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host due to the DNS
service." );
 script_set_attribute(attribute:"description", value:
"The remote host has the Windows DNS server installed.

There is a flaw in the remote version of this server that may allow an
attacker to execute arbitrary code on the remote host with SYSTEM
privileges.  To exploit this flaw, an attacker needs to connect to the
DNS server RPC interface and send malformed RPC queries." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released patches for Windows 2000 and 2003 Server :

http://www.microsoft.com/technet/security/Bulletin/MS07-029.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 935966";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
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


if ( hotfix_check_sp(win2003:3, win2k:6) <= 0 ) exit(0);
if ( ! get_kb_item("SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Services/DNS/DisplayName") ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:1, file:"Dns.exe", version:"5.2.3790.2915", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:2, file:"Dns.exe", version:"5.2.3790.4059", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Dns.exe", version:"5.0.2195.7135", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS07-029", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
