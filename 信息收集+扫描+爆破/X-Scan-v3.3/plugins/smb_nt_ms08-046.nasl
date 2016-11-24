#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(33875);
 script_version("$Revision: 1.6 $");

 script_cve_id("CVE-2008-2245");
 script_bugtraq_id(30594);
 script_xref(name:"OSVDB", value:"47395");

 name["english"] = "MS08-046: Vulnerability in Microsoft Windows Image Color Management System Could Allow Remote Code Execution (952954)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the Microsoft
Color Management System (MSCMS) module of the Microsoft ICM componenents." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Color Management Module which
is vulnerable to a security flaw which may allow an attacker to execute
arbitrary code on the remote host by crafting a malformed image file and
entice a victim to open it." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms08-046.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
 summary["english"] = "Determines the presence of update 952954";

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

if ( hotfix_check_sp(xp:4, win2003:3, win2k:6) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:2, file:"Mscms.dll", version:"5.2.3790.4320", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Mscms.dll", version:"5.2.3790.3163", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:3, file:"Mscms.dll", version:"5.1.2600.5627", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Mscms.dll", version:"5.1.2600.3396", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Mscms.dll", version:"5.0.2195.7162", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS08-046", value:TRUE);
 security_hole(get_kb_item("SMB/transport"));
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
