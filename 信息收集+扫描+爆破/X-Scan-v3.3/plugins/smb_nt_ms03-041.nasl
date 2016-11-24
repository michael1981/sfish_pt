#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11886);
 script_version("$Revision: 1.20 $");

 script_cve_id("CVE-2003-0660");
 script_bugtraq_id(8830);
 script_xref(name:"IAVA", value:"2003-B-0006");
 script_xref(name:"OSVDB", value:"11463");
 
 name["english"] = "MS03-041: Vulnerability in Authenticode Verification Could Allow Remote Code Execution (823182)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
client." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Authenticode Verification
module that may allow an attacker to execute arbitrary code on the
remote host by constructing a malicious web page and entice a victim
to visit this web page. 

An attacker may also be able to exploit the vulnerability by sending a
malicious HTML email." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000, XP and
2003 :

http://www.microsoft.com/technet/security/bulletin/ms03-041.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Checks for hotfix Q823182";
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

if ( hotfix_check_sp(nt:7, win2k:5, xp:2, win2003:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Cryptui.dll", version:"5.131.3790.67", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Cryptui.dll", version:"5.131.2600.1243", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Cryptui.dll", version:"5.131.2600.117", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Cryptui.dll", version:"5.131.2195.6758", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Cryptui.dll", version:"5.131.1878.14", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS03-041", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"KB823182") > 0 )
	 {
 set_kb_item(name:"SMB/Missing/MS03-041", value:TRUE);
 hotfix_security_hole();
 }

