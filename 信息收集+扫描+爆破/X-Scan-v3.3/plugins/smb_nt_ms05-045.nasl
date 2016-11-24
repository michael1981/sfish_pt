#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(19998);
 script_version("$Revision: 1.10 $");

 script_cve_id("CVE-2005-2307");
 script_xref(name:"IAVA", value:"2005-t-0042");
 script_xref(name:"OSVDB", value:"17885");

 name["english"] = "MS05-045: Vulnerability in Network Connection Manager Could Allow Denial of Service (905414)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"A flaw in the remote network connection manager may allow an attacker
to cause a denial of service on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Network Connection Manager
that contains a denial of service vulnerability that may allow an
attacker to disable the component responsible for managing network and
remote access connections. 

To exploit this vulnerability, an attacker would need to send a
malformed packet to the remote host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 
2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-045.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 905414";
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
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, arch:"x86", file:"netman.dll", version:"5.2.3790.396", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, arch:"x86", file:"netman.dll", version:"5.2.3790.2516", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"netman.dll", version:"5.1.2600.1733", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"netman.dll", version:"5.1.2600.2743", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0",       file:"netman.dll", version:"5.0.2195.7061", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS05-045", value:TRUE);
 hotfix_security_warning();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
