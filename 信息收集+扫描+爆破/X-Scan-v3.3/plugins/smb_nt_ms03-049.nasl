# 
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(11921);
 script_version("$Revision: 1.28 $");

 script_cve_id("CVE-2003-0812");
 script_bugtraq_id(9011);
 script_xref(name:"CERT", value:"CA-2003-28");
 script_xref(name:"IAVA", value:"2003-a-0018");
 script_xref(name:"IAVA", value:"2003-B-0008");
 script_xref(name:"OSVDB", value:"11461");
 
 name["english"] = "MS03-049: Buffer Overflow in the Workstation Service (828749)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a flaw in the function 
NetpValidateName() in the WorkStation service which may allow an 
attacker to execute arbitrary code on the remote host with the SYSTEM
privileges.

A series of worms (Welchia, Spybot, ...) are known to exploit this
vulnerability in the wild." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms03-049.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Checks for hotfix 828749";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
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

if (hotfix_check_sp(xp:2) > 0 )
{
 if (is_accessible_share())
 {
  if ( hotfix_is_vulnerable (os:"5.1", sp:1, file:"Msasn1.dll", version:"5.1.2600.1309", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.1", sp:0, file:"Msasn1.dll", version:"5.1.2600.121", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS03-049", value:TRUE);
 hotfix_security_hole();
 }
 
  hotfix_check_fversion_end();
  exit (0);
 }
 else if ( hotfix_missing(name:"828035") > 0) 
	 {
 set_kb_item(name:"SMB/Missing/MS03-049", value:TRUE);
 hotfix_security_hole();
 }
}

if ( hotfix_check_sp(win2k:5) > 0 )
{
 if (is_accessible_share())
 {
  if ( hotfix_is_vulnerable (os:"5.0", file:"wkssvc.dll", version:"5.0.2195.6862", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS03-049", value:TRUE);
 hotfix_security_hole();
 }

  hotfix_check_fversion_end();
  exit (0);
 }
 else if ( hotfix_missing(name:"828749") > 0 && hotfix_missing(name:"924270") > 0 ) 
	 {
 set_kb_item(name:"SMB/Missing/MS03-049", value:TRUE);
 hotfix_security_hole();
 }
}
