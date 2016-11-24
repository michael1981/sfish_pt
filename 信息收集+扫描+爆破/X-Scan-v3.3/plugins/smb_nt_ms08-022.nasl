#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(31795);
 script_version("$Revision: 1.7 $");

 script_cve_id("CVE-2008-0083");
 script_bugtraq_id(28551);
 script_xref(name:"OSVDB", value:"44210");
 script_xref(name:"OSVDB", value:"44211");

 name["english"] = "MS08-022: Vulnerability in VBScript and JScript Scripting Engines Could Allow Remote Code Execution (944338)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web or
email client." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows which contains a flaw
in JScript. 

An attacker may be able to execute arbitrary code on the remote host
by constructing a malicious JScript and enticing a victim to visit a
web site or view a specially-crafted email message." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/Bulletin/MS08-022.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );


script_end_attributes();

 
 summary["english"] = "Determines the presence of update 944338";

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



include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");



if ( hotfix_check_sp(xp:3, win2003:3, win2k:6) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:1, file:"Jscript.dll", version:"5.6.0.8835", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:2, file:"Jscript.dll", version:"5.6.0.8835", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Jscript.dll", version:"5.6.0.8835", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Jscript.dll", version:"5.6.0.8835", min_version:"5.6.0.0", dir:"\system32") 
   )
 {
 set_kb_item(name:"SMB/Missing/MS08-022", value:TRUE);
 hotfix_security_warning();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
