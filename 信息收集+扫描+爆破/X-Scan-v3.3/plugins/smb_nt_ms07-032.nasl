#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(25485);
 script_version("$Revision: 1.9 $");

 script_cve_id("CVE-2007-2229");
 script_bugtraq_id(24411);
 script_xref(name:"OSVDB", value:"35344");

 name["english"] = "MS07-032: Vulnerability in Windows Vista Could Allow Information Disclosure (931213)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"A local user can access sensitive information." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows with a bug in the User
Information Store ACLs that may allow a local attacker to access
privileged information in the registry or on the disk." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista :

http://www.microsoft.com/technet/security/Bulletin/MS07-032.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 931213";

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

if ( hotfix_check_sp(vista:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"6.0", sp:0, file:"Imagehlp.dll", version:"6.0.6000.16470", dir:"\System32") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Imagehlp.dll", version:"6.0.6000.20580", min_version:"6.0.6000.20000", dir:"\System32") )
 {
 set_kb_item(name:"SMB/Missing/MS07-032", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
