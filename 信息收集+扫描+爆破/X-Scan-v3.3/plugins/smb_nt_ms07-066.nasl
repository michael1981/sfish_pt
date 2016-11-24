#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(29310);
 script_version("$Revision: 1.7 $");

 script_cve_id("CVE-2007-5350");
 script_bugtraq_id(26757);
 script_xref(name:"OSVDB", value:"39124");

 name["english"] = "MS07-066: Vulnerability in Windows Kernel Could Allow Elevation of Privilege (943078)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"A local user can elevate his privileges on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Windows kernel which is vulnerable
to a security flaw which may allow a local user to elevate his privileges
or to crash it (therefore causing a denial of service)." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista:

http://www.microsoft.com/technet/security/bulletin/ms07-066.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Checks the remote registry for 943078";

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
 if ( 
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Ntoskrnl.exe", version:"6.0.6000.16575", dir:"\System32") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Ntoskrnl.exe", version:"6.0.6000.20697", min_version:"6.0.6000.20000", dir:"\System32")     )
 {
 set_kb_item(name:"SMB/Missing/MS07-066", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
