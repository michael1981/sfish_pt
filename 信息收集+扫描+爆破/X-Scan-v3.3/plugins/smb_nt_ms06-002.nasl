#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(20389);
 script_version("$Revision: 1.10 $");

 script_cve_id("CVE-2006-0010");
 script_bugtraq_id(16194);
 script_xref(name:"OSVDB", value:"18829");
 
 name["english"] = "MS06-002: Vulnerability in Embedded Web Fonts Could Allow Remote Code Execution (908519)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host by sending a
malformed file to a victim." );
 script_set_attribute(attribute:"description", value:
"The remote version of Microsoft Windows contains a flaw in the
Embedded Web Font engine.  An attacker may execute arbitrary code on
the remote host by constructing a malicious web page and entice a
victim to visit this web page or by sending a malicious font file." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 
2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-002.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 908519";
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
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Fontsub.dll", version:"5.2.3790.426", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Fontsub.dll", version:"5.2.3790.2549", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Fontsub.dll", version:"5.1.2600.1762", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Fontsub.dll", version:"5.1.2600.2777", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0",       file:"Fontsub.dll", version:"5.0.2195.7071", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS06-002", value:TRUE);
 hotfix_security_hole();
 }
      hotfix_check_fversion_end(); 
}
