#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(31039);
 script_cve_id("CVE-2008-0074");
 script_bugtraq_id(27101);
 script_xref(name:"OSVDB", value:"41456");
 script_version("$Revision: 1.8 $");
 name["english"] = "MS08-005: Vulnerability in Internet Information Services Could Allow Elevation of Privilege (942831)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"A local user can elevate his privileges on the remote host" );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of Microsoft Internet Information
Services (IIS) which is vulnerable to a security flaw which may allow
a local user to elevate his privileges to SYSTEM due to a bug in the
way IIS handles file change notifications in the FTPRoot,
NNTPFile\Root and WWWRoot folders." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, Windows XP,
Windows 2003 Server and Windows Vista :

http://www.microsoft.com/technet/security/bulletin/ms08-005.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Checks the remote file version for 942831";

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

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");



if ( ! get_kb_item("SMB/WindowsVersion") ) exit(1);
if ( hotfix_check_iis_installed() <= 0 ) exit(1);


if ( hotfix_check_sp(win2k:6, win2003:3, xp:3, vista:1) <= 0 ) exit(0);
if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"6.0", sp:0, file:"infocomm.dll", version:"7.0.6000.20698", min_version:"7.0.6000.20000", dir:"\system32\inetsrv") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"infocomm.dll", version:"7.0.6000.16576", dir:"\system32\inetsrv") ||
      hotfix_is_vulnerable (os:"5.2", sp:2, file:"infocomm.dll", version:"6.0.3790.4215", dir:"\system32\inetsrv") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"infocomm.dll", version:"6.0.3790.3068", dir:"\system32\inetsrv") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"infocomm.dll", version:"6.0.2600.3290", dir:"\system32\inetsrv") ||
      hotfix_is_vulnerable (os:"5.0", file:"infocomm.dll", version:"5.0.2195.7147", dir:"\system32\inetsrv") )
      	 {
 set_kb_item(name:"SMB/Missing/MS08-005", value:TRUE);
 hotfix_security_warning();
 }

  hotfix_check_fversion_end(); 
}
