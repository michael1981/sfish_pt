#
# (C) Tenable Network Security
#

include("compat.inc");

if(description)
{
 script_id(23834);
 script_bugtraq_id(21550);
 script_xref(name:"OSVDB", value:"30812");
 script_cve_id("CVE-2006-5585");

 script_version("$Revision: 1.9 $");
 name["english"] = "MS06-075: Vulnerability in Windows Could Allow Elevation of Privilege (926255)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"A local user can elevate his privileges on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Windows System which is vulnerable
to a security flaw which may allow a local user to elevate his privileges
or to crash it (therefore causing a denial of service)." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP and 2003:

http://www.microsoft.com/technet/security/bulletin/ms06-075.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Determines if hotfix 926255 has been installed";

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

if ( hotfix_check_sp(xp:3, win2003:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Sxs.dll", version:"5.2.3790.599", dir:"\system32") || 
      hotfix_is_vulnerable (os:"5.1", file:"Sxs.dll", version:"5.1.2600.3019", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS06-075", value:TRUE);
 hotfix_security_warning();
 }
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"926255") > 0  )
{
 {
 set_kb_item(name:"SMB/Missing/MS06-075", value:TRUE);
 hotfix_security_warning();
 }
}

