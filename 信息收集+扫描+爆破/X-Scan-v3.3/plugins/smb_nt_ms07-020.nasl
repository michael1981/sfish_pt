#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(25023);
 script_version("$Revision: 1.10 $");

 script_cve_id("CVE-2007-1205");
 script_bugtraq_id(23337);
 script_xref(name:"OSVDB", value:"34009");
 
 name["english"] = "MS07-020: Vulnerability in Microsoft Agent Could Allow Remote Code Execution (932168)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web or
email client." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a flaw in the Microsoft Agent
service that may allow an attacker to execute code on the remote host. 

To exploit this flaw, an attacker would need to set up a rogue web
site and lure a victim on the remote host into visiting it." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003 and
Vista :

http://www.microsoft.com/technet/security/bulletin/ms07-020.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 932168";

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


include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");


if ( hotfix_check_sp(xp:3, win2003:3, win2k:6) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, arch:"x86", file:"Agentdpv.dll", version:"2.0.0.3425", dir:"\msagent") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, arch:"x86", file:"Agentdpv.dll", version:"5.2.3790.1243", dir:"\msagent") ||
      hotfix_is_vulnerable (os:"5.2", sp:2, arch:"x86", file:"Agentdpv.dll", version:"5.2.3790.1243", dir:"\msagent") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Agentdpv.dll", version:"2.0.0.3425", dir:"\msagent") ||
      hotfix_is_vulnerable (os:"5.0", file:"Agentdpv.dll", version:"2.0.0.3425", dir:"\msagent") )
 {
 set_kb_item(name:"SMB/Missing/MS07-020", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}

