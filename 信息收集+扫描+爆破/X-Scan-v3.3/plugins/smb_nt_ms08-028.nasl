#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(32312);
 script_version("$Revision: 1.7 $");

 script_cve_id("CVE-2005-0944", "CVE-2007-6026");
 script_bugtraq_id(12960, 26468);
 script_xref(name:"OSVDB", value:"15187");
 script_xref(name:"OSVDB", value:"44880");
 
 name["english"] = "MS08-028: Vulnerability in Microsoft Jet Database Engine Could Allow Remote Code Execution (950749)";

 script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through database
engine." );
 script_set_attribute(attribute:"description", value:
"The remote host has a bug in its Microsoft Jet Database Engine
(837001). 

An attacker may exploit one of these flaws to execute arbitrary code
on the remote system. 

To exploit this flaw, an attacker would need the ability to craft a
specially malformed database query and have this engine execute it." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms08-028.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Checks for ms08-028";

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

if ( hotfix_check_sp(win2k:6, xp:3, win2003:2) <= 0 ) exit(0);


if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:1, arch:"x86", file:"Msjet40.dll", version:"4.0.9511.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, arch:"x64", file:"Wmsjet40.dll", version:"4.0.9511.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Msjet40.dll", version:"4.0.9511.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Msjet40.dll", version:"4.0.9511.0", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS08-028", value:TRUE);
 security_hole(get_kb_item("SMB/transport"));
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
