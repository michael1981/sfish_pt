#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(13637);
 script_version("$Revision: 1.15 $");

 script_cve_id("CVE-2004-0213");
 script_bugtraq_id(10707);
 script_xref(name:"IAVA", value:"2004-t-0019");
 script_xref(name:"OSVDB", value:"7792");

 name["english"] = "MS04-019: Utility Manager Could Allow Code Execution (842526)";
 script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"Local users can elevate their privileges." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the Utility Manager that may
allow a local attacker to execute arbitrary code on the host, thus
escalating his privileges and obtaining the full control of the remote
system." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000 :

http://www.microsoft.com/technet/security/bulletin/ms04-019.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Checks for ms04-019 over the registry";
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

if ( hotfix_check_sp(win2k:5) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.0", file:"Umandlg.dll", version:"1.0.0.5", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS04-019", value:TRUE);
 security_hole(get_kb_item("SMB/transport"));
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"KB842526") > 0 ) 
	 {
 set_kb_item(name:"SMB/Missing/MS04-019", value:TRUE);
 hotfix_security_hole();
 }
