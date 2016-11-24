#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(15963);
 script_version("$Revision: 1.14 $");

 script_cve_id("CVE-2004-0893", "CVE-2004-0894");
 script_bugtraq_id(11913, 11914);
 script_xref(name:"IAVA", value:"2004-t-0040");
 script_xref(name:"OSVDB", value:"12372");
 script_xref(name:"OSVDB", value:"12376");

 name["english"] = "MS04-044: Vulnerabilities in Windows Kernel and LSASS (885835)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Local users can elevate their privileges on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running version of the NT kernel and LSASS which
may allow a local user to gain elevated privileged. 

An attacker who has the ability to execute arbitrary commands on the
remote host may exploit these flaws to gain SYSTEM privileges." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000, XP and
2003 :

http://www.microsoft.com/technet/security/bulletin/ms04-044.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Checks the remote registry for MS04-044";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
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

if ( hotfix_check_sp(nt:7, xp:3, win2k:5, win2003:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Lsasrv.dll", version:"5.2.3790.220", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Lsasrv.dll", version:"5.1.2600.1597", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Lsasrv.dll", version:"5.1.2600.2525", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Lsasrv.dll", version:"5.0.2195.6987", dir:"\system32") || 
      hotfix_is_vulnerable (os:"4.0", file:"Ntoskrnl.exe", version:"4.0.1381.7268", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS04-044", value:TRUE);
 security_hole(get_kb_item("SMB/transport"));
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"885835") > 0 )
	 {
 set_kb_item(name:"SMB/Missing/MS04-044", value:TRUE);
 hotfix_security_hole();
 }
