#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(20002);
 script_version("$Revision: 1.11 $");

 script_cve_id("CVE-2005-2122", "CVE-2005-2118", "CVE-2005-2117");
 script_bugtraq_id(15070, 15069, 15064);
 script_xref(name:"IAVA", value:"2005-A-0027");
 script_xref(name:"OSVDB", value:"19898");
 script_xref(name:"OSVDB", value:"19899");
 script_xref(name:"OSVDB", value:"19900");

 name["english"] = "MS05-049: Vulnerabilities in Windows Shell Could Allow Remote Code Execution (900725)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Vulnerabilities in the Windows Shell may allow an attacker to execute
arbitrary code on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a version of the Windows Shell
that has several vulnerabilities.  An attacker may exploit these
vulnerabilities by :

 - Sending a malformed .lnk file a to user on the remote host to
   trigger an overflow.

 - Sending a malformed HTML document to a user on the remote host and
   have him view it in the Windows Explorer preview pane." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 
2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-049.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 900725";
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
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"shell32.dll", version:"6.0.3790.413", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"shell32.dll", version:"6.0.3790.2534", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"shell32.dll", version:"6.0.2800.1751", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"shell32.dll", version:"6.0.2900.2763", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0",       file:"shell32.dll", version:"5.0.3900.7071", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS05-049", value:TRUE);
 hotfix_security_hole();
 }
 hotfix_check_fversion_end(); 
}
