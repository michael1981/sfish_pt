#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(22030);
 script_version("$Revision: 1.11 $");
 script_cve_id("CVE-2006-2372");
 script_bugtraq_id(18923);
 script_xref(name:"OSVDB", value:"27151");
 
 name["english"] = "MS06-036: Vulnerability in DHCP Client Service Could Allow Remote Code Execution (914388)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host due to a flaw in the 
DHCP client." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a DHCP client which is vulnerable to a buffer
overrun attack when receiving a malformed response to a DHCP request. 

An attacker may exploit this flaw to execute arbitrary code on the
remote host with 'SYSTEM' privileges. 

Typically, the attacker would need to be on the same physical subnet
as this victim to exploit this flaw.  Also, the victim needs to be
configured to use DHCP." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 
2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-036.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 914388";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");


if ( hotfix_check_sp(xp:3, win2003:2, win2k:6) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Dhcpcsvc.dll", version:"5.2.3790.536", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Dhcpcsvc.dll", version:"5.2.3790.2706", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Dhcpcsvc.dll", version:"5.1.2600.1847", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Dhcpcsvc.dll", version:"5.1.2600.2912", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Dhcpcsvc.dll", version:"5.0.2195.7085", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS06-036", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}

