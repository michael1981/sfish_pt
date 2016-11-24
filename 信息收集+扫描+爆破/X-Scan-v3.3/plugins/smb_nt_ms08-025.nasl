#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(31798);
 script_version("$Revision: 1.8 $");

 script_cve_id("CVE-2008-1084");
 script_bugtraq_id(28554);
 script_xref(name:"OSVDB", value:"44206");

 name["english"] = "MS08-025: Vulnerability in Windows Kernel Could Allow Elevation of Privilege (941693)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"A local user can elevate his privileges on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Windows kernel which is vulnerable
to a security flaw which may allow a local user to elevate his privileges
or to crash it (therefore causing a denial of service)." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003, Vista, 2008:

http://www.microsoft.com/technet/security/bulletin/ms08-025.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Checks the remote registry for 941693";

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


if ( hotfix_check_sp(xp:3, win2003:3, win2k:6, vista:2) <= 0 ) exit(0);

if (is_accessible_share())
{
      if ( hotfix_is_vulnerable (os:"6.0", sp:1, file:"Win32k.sys", version:"6.0.6001.22125", min_version:"6.0.6001.20000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:1, file:"Win32k.sys", version:"6.0.6001.18027", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Win32k.sys", version:"6.0.6000.20782", min_version:"6.0.6000.20000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Win32k.sys", version:"6.0.6000.16646", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:2, file:"Win32k.sys", version:"5.2.3790.4256", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Win32k.sys", version:"5.2.3790.3106", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Win32k.sys", version:"5.1.2600.3335", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Win32k.sys", version:"5.0.2195.7154", dir:"\system32") )
   	 {
 set_kb_item(name:"SMB/Missing/MS08-025", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end();
 exit (0);
}
