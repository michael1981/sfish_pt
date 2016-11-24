#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(21686);
 script_version("$Revision: 1.10 $");

 script_cve_id("CVE-2006-2378");
 script_bugtraq_id(18394);
 script_xref(name:"OSVDB", value:"26432");

 name["english"] = "MS06-022: Vulnerability in ART Image Rendering Could Allow Remote Code Execution (918439)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
client." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows which contains a flaw
in the Hyperlink Object Library. 

An attacker may exploit this flaw to execute arbitrary code on the
remote host. 

To exploit this flaw, an attacker would need to construct a malicious
hyperlink and lure a victim into clicking it." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP and 2003 :

http://www.microsoft.com/technet/security/Bulletin/MS06-022.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );


script_end_attributes();

 
 summary["english"] = "Determines the presence of update 918439";

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



include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");


rootfile = hotfix_get_systemroot();
if(!rootfile) exit(0);

port = kb_smb_transport ();

if ( hotfix_check_sp(xp:3, win2003:2, win2k:5) <= 0 ) exit(0);

if (is_accessible_share())
{
 rootfile = rootfile + "\system32";
 if ( hotfix_is_vulnerable (os:"5.2", arch:"x86", file:"Jgdw400.dll", version:"106.0.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", arch:"x64", file:"Wjgdw400.dll", version:"106.0.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", file:"Jgdw400.dll", version:"106.0.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Jgdw400.dll", version:"106.0.0.0", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS06-022", value:TRUE);
 hotfix_security_warning();
 }

   hotfix_check_fversion_end();
}
