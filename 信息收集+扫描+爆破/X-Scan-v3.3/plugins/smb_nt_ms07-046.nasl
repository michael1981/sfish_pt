#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(25884);
 script_version("$Revision: 1.11 $");

 script_cve_id("CVE-2007-3034");
 script_bugtraq_id(25302);
 script_xref(name:"OSVDB", value:"36388");
 
 name["english"] = "MS07-046: Vulnerability in GDI Could Allow Remote Code Execution (938829)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host by sending a
malformed file to a victim." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of Microsoft Windows that has
several vulnerabilities in the Graphic Rendering Engine and in the
way Windows handles Metafiles. 

An attacker may exploit these flaws to execute arbitrary code on the
remote host.  To exploit this flaw, an attacker would need to send a
specially crafted image to a user on the remote host, or lure him into
visiting a rogue website containing such a file." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003 and
Vista :

http://www.microsoft.com/technet/security/bulletin/ms07-046.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 938829";
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


if ( hotfix_check_sp(xp:3, win2003:2, win2k:6) <= 0 ) exit(0);
if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:1, file:"gdi32.dll", version:"5.2.3790.2960", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"gdi32.dll", version:"5.1.2600.3159", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0",       file:"gdi32.dll", version:"5.0.2195.7138", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS07-046", value:TRUE);
 hotfix_security_hole();
 }
      hotfix_check_fversion_end(); 
}
