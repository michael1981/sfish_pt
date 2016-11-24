#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(13642);
 script_version("$Revision: 1.14 $");

 script_cve_id("CVE-2004-0420");
 script_bugtraq_id(9510);
 script_xref(name:"IAVA", value:"2004-B-0010");
 script_xref(name:"OSVDB", value:"7802");
 
 name["english"] = "MS04-024: Buffer overrun in Windows Shell (839645)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute commands on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows which has a flaw in 
its shell. An attacker could persuade a user on the remote host to execute
a rogue program by using a CLSID instead of a file type, thus fooling
the user into thinking that he will not execute an application but simply
open a document." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms04-024.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Checks for ms04-024 over the registry";

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

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( hotfix_check_sp(nt:7, win2k:5, xp:2, win2003:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Shell32.dll", version:"6.0.3790.168", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Shell32.dll", version:"6.0.2800.1556", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Shell32.dll", version:"6.0.2750.151", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Shell32.dll", version:"5.0.3900.6922", dir:"\system32") || 
      hotfix_is_vulnerable (os:"4.0", file:"Shell32.dll", version:"4.0.1381.7267", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS04-024", value:TRUE);
 security_hole(get_kb_item("SMB/transport"));
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"839645") > 0 &&
     hotfix_missing(name:"841356") > 0  )
	 {
 set_kb_item(name:"SMB/Missing/MS04-024", value:TRUE);
 hotfix_security_hole();
 }

