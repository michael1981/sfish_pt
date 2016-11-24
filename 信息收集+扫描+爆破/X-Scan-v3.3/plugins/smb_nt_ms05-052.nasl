#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(20005);
 script_version("$Revision: 1.24 $");

 script_cve_id("CVE-2005-2127");
 script_bugtraq_id(14594, 15061);
 script_xref(name:"IAVA", value:"2005-A-0028");
 script_xref(name:"IAVA", value:"2005-t-0032");
 script_xref(name:"OSVDB", value:"2692");
 script_xref(name:"OSVDB", value:"19093");
 
 script_name(english:"MS05-052: Cumulative Security Update for Internet Explorer (896688)");
 script_summary(english:"Determines the presence of update 896688");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web client." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Internet Explorer which is
vulnerable to a security flaw (COM Object Instantiation Memory Corruption
Vulnerability) which may allow an attacker to execute arbitrary code on the
remote host by constructing a malicious web page and entice a victim 
to visit this web page." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP SP2 and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-052.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
 script_end_attributes();
 
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
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Mshtml.dll", version:"6.0.3790.418", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Mshtml.dll", version:"6.0.3790.2541", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Mshtml.dll", version:"6.0.2900.2769", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Mshtml.dll", version:"6.0.2800.1522", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Mshtml.dll", version:"6.0.2800.1522", min_version:"6.0.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Mshtml.dll", version:"5.0.3833.200", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS05-052", value:TRUE);
 security_hole(get_kb_item("SMB/transport"));
 }
 else
   set_kb_item (name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Updates/KB896688", value:TRUE);
 
 hotfix_check_fversion_end(); 
 exit (0);
}
