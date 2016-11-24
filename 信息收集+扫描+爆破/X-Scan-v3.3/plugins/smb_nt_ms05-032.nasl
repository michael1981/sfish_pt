#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(18485);
 script_version("$Revision: 1.16 $");

 script_cve_id("CVE-2005-1214");
 script_bugtraq_id(13948);
 script_xref(name:"IAVA", value:"2005-t-0022");
 script_xref(name:"OSVDB", value:"17310");

 name["english"] = "MS05-032: Vulnerability in Microsoft Agent Could Allow Spoofing (890046)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to spoof the content of a web site." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a flaw in the Microsoft Agent
service that may allow an attacker to spoof the content of a web site. 

To exploit this flaw, an attacker would need to set up a rogue web
site and lure a victim on the remote host into visiting it." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 
2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-032.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 890046";
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


include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");


if ( hotfix_check_sp(xp:3, win2003:2, win2k:6) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Agentdpv.dll", version:"2.0.0.3423", dir:"\msagent") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Agentdpv.dll", version:"5.2.3790.1241", dir:"\msagent") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Agentdpv.dll", version:"2.0.0.3423", dir:"\msagent") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Agentdpv.dll", version:"2.0.0.3423", dir:"\msagent") ||
      hotfix_is_vulnerable (os:"5.0", file:"Agentdpv.dll", version:"2.0.0.3423", dir:"\msagent") )
 {
 set_kb_item(name:"SMB/Missing/MS05-032", value:TRUE);
 security_warning(get_kb_item("SMB/transport"));
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}

