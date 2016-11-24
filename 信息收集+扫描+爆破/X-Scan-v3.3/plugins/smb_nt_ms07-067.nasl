#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(29311);
 script_version("$Revision: 1.7 $");

 script_cve_id("CVE-2007-5587");
 script_bugtraq_id(26121);
 script_xref(name:"OSVDB", value:"41429");

 name["english"] = "MS07-067: Vulnerability in Macrovision Driver Could Allow Local Elevation of Privilege (944653)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a kernel driver that is prone to a
local privilege escalation vulnerability." );
 script_set_attribute(attribute:"description", value:
"Macrovision SafeDisc, a copy-protection application for Microsoft
Windows, is installed on the remote host. 

The 'SECDRV.SYS' driver included with the version of SafeDisc
currently installed on the remote host enables a local user to gain
SYSTEM privileges using a specially-crafted argument to the
METHOD_NEITHER IOCTL." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms07-067.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Determines the presence of update 944653";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl", "macrovision_secdrv_priv_escalation.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


if ( hotfix_check_sp(xp:3) > 0 )
{
 if (is_accessible_share() )
 {
 if ( get_kb_item("Host/SMB/secdrv/CVE-2007-5587" ) ) 
	 {
 set_kb_item(name:"SMB/Missing/MS07-067", value:TRUE);
 hotfix_security_warning();
 }
 }
 else if (hotfix_missing(name:"944653") > 0 )
 {
 set_kb_item(name:"SMB/Missing/MS07-067", value:TRUE);
 hotfix_security_warning();
 }
 
}

if ( hotfix_check_sp(win2003:3) <= 0 ) exit(0);
if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", file:"secdrv.sys", version:"4.3.86.0", dir:"\system32\drivers") )
 {
 set_kb_item(name:"SMB/Missing/MS07-067", value:TRUE);
 hotfix_security_warning();
 }
      hotfix_check_fversion_end(); 
}
else if (hotfix_missing(name:"944653") > 0 )
 {
 set_kb_item(name:"SMB/Missing/MS07-067", value:TRUE);
 hotfix_security_warning();
 }
