#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(26017);
 script_version("$Revision: 1.6 $");

 script_cve_id("CVE-2007-3040");
 script_bugtraq_id(25566);
 script_xref(name:"OSVDB", value:"36934");
 
 name["english"] = "MS07-051: Vulnerability in Microsoft Agent Could Allow Remote Code Execution (938827)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web or
email client." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a flaw in the Microsoft Agent
service that may allow an attacker to execute code on the remote host. 

To exploit this flaw, an attacker would need to set up a rogue web
site and lure a victim on the remote host into visiting it." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000 :

http://www.microsoft.com/technet/security/bulletin/ms07-051.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
 summary["english"] = "Determines the presence of update 938827";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
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


if ( hotfix_check_sp(win2k:6) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.0", file:"Agentdpv.dll", version:"2.0.0.3426", dir:"\msagent") )
 {
 set_kb_item(name:"SMB/Missing/MS07-051", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"938827") > 0 )
	 {
 set_kb_item(name:"SMB/Missing/MS07-051", value:TRUE);
 hotfix_security_hole();
 }


