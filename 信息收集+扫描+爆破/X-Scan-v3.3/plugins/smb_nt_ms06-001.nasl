#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(20382);
 script_version("$Revision: 1.15 $");

 script_cve_id("CVE-2005-4560");
 script_bugtraq_id(16074);
 script_xref(name:"OSVDB", value:"21987");
 
 name["english"] = "MS06-001: Vulnerabilities in Graphics Rendering Engine Could Allow Code Execution (912919)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host by sending a
malformed file to a victim." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of Microsoft Windows is missing a
critical security update which fixes several vulnerabilities in the
Graphic Rendering Engine, and in the way Windows handles Metafiles. 

An attacker may exploit these flaws to execute arbitrary code on the
remote host.  To exploit this flaw, an attacker would need to send a
specially crafted Windows Metafile (WMF) to a user on the remote host,
or lure him into visiting a rogue website containing such a file." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP SP2 and
2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-001.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 912919";
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


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


if ( hotfix_check_sp(xp:3, win2003:2, win2k:6) <= 0 ) exit(0);
if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"gdi32.dll", version:"5.2.3790.462", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"gdi32.dll", version:"5.2.3790.2606", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"gdi32.dll", version:"5.1.2600.1789", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"gdi32.dll", version:"5.1.2600.2818", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0",       file:"gdi32.dll", version:"5.0.2195.7073", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS06-001", value:TRUE);
 hotfix_security_hole();
 }
      hotfix_check_fversion_end(); 
}
