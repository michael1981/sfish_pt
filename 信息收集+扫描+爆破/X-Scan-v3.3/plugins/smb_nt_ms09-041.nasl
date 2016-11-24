# 
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(40560);
 script_version("$Revision: 1.2 $");

 script_cve_id("CVE-2009-1544");
 script_bugtraq_id(35972);
 script_xref(name:"OSVDB", value:"56902");
 
 script_name(english:"MS09-041: Vulnerability in Workstation Service Could Allow Elevation of Privilege (971657)");
 script_summary(english:"Checks for hotfix 971657");
 
 script_set_attribute(attribute:"synopsis", value:
"Users can elevate their privileges on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the 'Workstation' service that
contains a memory corruption vulnerability that might allow an
attacker with valid credentials to execute arbitrary code on the
remote host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista and 
Server 2008 :

http://www.microsoft.com/technet/security/bulletin/ms09-041.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C" );

 script_set_attribute(
  attribute:"patch_publication_date", 
  value:"2009/08/11"
 );
 script_set_attribute(
  attribute:"plugin_publication_date", 
  value:"2009/08/11"
 );
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows : Microsoft Bulletins");

 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if (hotfix_check_sp(xp:4, win2003:3, vista:3) > 0 )
{
 if (is_accessible_share())
 {
  if ( hotfix_is_vulnerable (os:"5.1", sp:2, file:"wkssvc.dll", version:"5.1.2600.3584", dir:"\system32")  ||
       hotfix_is_vulnerable (os:"5.1", sp:3, file:"wkssvc.dll", version:"5.1.2600.5826", dir:"\system32")  ||
       hotfix_is_vulnerable (os:"5.2", sp:2, file:"wkssvc.dll", version:"5.2.3790.4530", dir:"\system32")  ||
       hotfix_is_vulnerable (os:"6.0", sp:0, file:"wkssvc.dll", version:"6.0.6000.16868", dir:"\system32")  ||
       hotfix_is_vulnerable (os:"6.0", sp:0, file:"wkssvc.dll", version:"6.0.6000.21065", min_version:"6.0.6000.21000", dir:"\system32") ||
       hotfix_is_vulnerable (os:"6.0", sp:1, file:"wkssvc.dll", version:"6.0.6001.18270", dir:"\system32") ||
       hotfix_is_vulnerable (os:"6.0", sp:1, file:"wkssvc.dll", version:"6.0.6001.22447", min_version:"6.0.6001.22000", dir:"\system32") ||
       hotfix_is_vulnerable (os:"6.0", sp:2, file:"wkssvc.dll", version:"6.0.6002.18049", dir:"\system32") ||
       hotfix_is_vulnerable (os:"6.0", sp:2, file:"wkssvc.dll", version:"6.0.6002.22150", min_version:"6.0.6002.22000", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS09-041", value:TRUE);
 hotfix_security_hole();
 }

  hotfix_check_fversion_end();
  exit (0);
 }
}
