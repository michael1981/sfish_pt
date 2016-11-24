#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(31794);
 script_version("$Revision: 1.7 $");
 script_cve_id("CVE-2008-1083", "CVE-2008-1087");
 script_bugtraq_id(28570, 28571);
 script_xref(name:"OSVDB", value:"44213");
 script_xref(name:"OSVDB", value:"44214");
 script_xref(name:"OSVDB", value:"44215");
 
 name["english"] = "MS08-021: Vulnerabilities in GDI Could Allow Remote Code Execution (948590)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host by sending a malformed file
to a victim." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of Microsoft Windows is missing a critical
security update which fixes several vulnerabilities in the Graphic Rendering
Engine, and in the way Windows handles Metafiles.

An attacker may exploit these flaws to execute arbitrary code on the remote
host. To exploit this flaw, an attacker would need to send a specially 
crafted image to a user on the remote host, or lure him into visiting a rogue
website containing such a file." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003 and Vista :

http://www.microsoft.com/technet/security/bulletin/ms08-021.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );



script_end_attributes();

 
 summary["english"] = "Determines the presence of update 948590";

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


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


if ( hotfix_check_sp(xp:3, win2003:3, win2k:6, vista:2, win2008:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( 
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"gdi32.dll", version:"6.0.6000.20777", min_version:"6.0.6000.20000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:1, file:"gdi32.dll", version:"6.0.6001.22120", min_version:"6.0.6001.20000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"gdi32.dll", version:"6.0.6000.16643", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:1, file:"gdi32.dll", version:"6.0.6001.18023", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"gdi32.dll", version:"5.2.3790.3091", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:2, file:"gdi32.dll", version:"5.2.3790.4237", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"gdi32.dll", version:"5.1.2600.3316", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0",       file:"gdi32.dll", version:"5.0.2195.7153", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS08-021", value:TRUE);
 hotfix_security_hole();
 }

      hotfix_check_fversion_end(); 
}
