#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(19403);
 script_version("$Revision: 1.13 $");
 script_cve_id("CVE-2005-0058");
 script_bugtraq_id(14518);
 script_xref(name:"OSVDB", value:"18606");

 name["english"] = "MS05-040: Vulnerability in Telephony Service Could Allow Remote Code Execution (893756)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host due to a flaw in the 
Telephony service." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Telephony service which is
vulnerable to a security flaw which may allow an attacker to execute
arbitrary code and take control of the remote host.

On Windows 2000 and Windows 2003 the server must be enabled and only
authenticated user can try to exploit this flaw.

On Windows 2000 Pro and Windows XP this is a local elevation of
privilege vulnerability." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-040.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
 summary["english"] = "Determines the presence of update 893756";

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
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Tapisrv.dll", version:"5.2.3790.366", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Tapisrv.dll", version:"5.2.3790.2483", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Tapisrv.dll", version:"5.1.2600.1715", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Tapisrv.dll", version:"5.1.2600.2716", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", sp:4, file:"Tapisrv.dll", version:"5.0.2195.7057", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS05-040", value:TRUE);
 security_hole(get_kb_item("SMB/transport"));
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
