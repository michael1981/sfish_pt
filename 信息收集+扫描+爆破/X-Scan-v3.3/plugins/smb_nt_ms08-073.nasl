#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(35072);
 script_version("$Revision: 1.6 $");

 script_cve_id("CVE-2008-4258", "CVE-2008-4259", "CVE-2008-4260", "CVE-2008-4261");
 script_bugtraq_id(32586, 32593, 32595, 32596);
 script_xref(name:"OSVDB", value:"50610");
 script_xref(name:"OSVDB", value:"50611");
 script_xref(name:"OSVDB", value:"50612");
 script_xref(name:"OSVDB", value:"50613");

 script_name(english: "MS08-073: Microsoft Internet Explorer Multiple Vulnerabilities (958215)");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web client." );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the IE cumulative security update 958215.

The remote version of IE is vulnerable to several flaws which may allow an 
attacker to execute arbitrary code on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003, Vista and 2008:

http://www.microsoft.com/technet/security/Bulletin/MS08-073.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
 summary["english"] = "Determines the presence of update 958215";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
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


if ( hotfix_check_sp(xp:4, win2003:3, win2k:6, vista:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( 
      hotfix_is_vulnerable (os:"6.0", sp:1, file:"Mshtml.dll", version:"7.0.6001.22288", min_version:"7.0.6001.20000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:1, file:"Mshtml.dll", version:"7.0.6001.18157", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Mshtml.dll", version:"7.0.6000.20937", min_version:"7.0.6000.20000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Mshtml.dll", version:"7.0.6000.16764", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Mshtml.dll", version:"6.0.3790.3229", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:2, file:"Mshtml.dll", version:"6.0.3790.4392", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", file:"Mshtml.dll", version:"7.0.6000.20935", min_version:"7.0.6000.20000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", file:"Mshtml.dll", version:"7.0.6000.16762", min_version:"7.0.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", file:"Mshtml.dll", version:"7.0.6000.20935", min_version:"7.0.6000.20000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", file:"Mshtml.dll", version:"7.0.6000.16762", min_version:"7.0.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:3, file:"Mshtml.dll", version:"6.0.2900.5694", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Mshtml.dll", version:"6.0.2900.3462", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Mshtml.dll", version:"6.0.2800.1617", min_version:"6.0.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Mshtml.dll", version:"5.0.3870.1500", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS08-073", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
