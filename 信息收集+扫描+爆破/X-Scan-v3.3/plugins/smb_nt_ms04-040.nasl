#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(15894);
 script_version("$Revision: 1.24 $");

 script_cve_id("CVE-2004-1050");
 script_xref(name:"IAVA", value:"2004-A-0020");
 script_xref(name:"OSVDB", value:"11337");
 
 name["english"] = "MS04-040: Cumulative Security Update for Internet Explorer (889293)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
client." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Internet Explorer 6 SP1 that
may allow an attacker to execute arbitrary code on the remote host. 

To exploit this flaw, an attacker would need to lure a victim on the
remote system into visiting a rogue website." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms04-040.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Checks for hotfix 889293";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/registry_full_access","SMB/WindowsVersion");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


if ( hotfix_check_sp(nt:7, win2k:5, xp:2) <= 0 ) exit(0);
if ( hotfix_missing(name:"867282") == 0 ) exit(0); 
if ( hotfix_missing(name:"890923") == 0 ) exit(0); 
if ( hotfix_missing(name:"883939") == 0 ) exit(0); 
if ( hotfix_missing(name:"896727") <= 0 ) exit(0); 
if ( hotfix_missing(name:"896688") <= 0 ) exit(0); 
if ( hotfix_missing(name:"905915") <= 0 ) exit(0); 
if ( hotfix_missing(name:"910620") <= 0 ) exit(0);
if ( hotfix_missing(name:"912812") <= 0 ) exit(0);
if ( hotfix_missing(name:"916281") <= 0 ) exit(0);
if ( hotfix_missing(name:"918899") <= 0 ) exit(0); 
if ( hotfix_missing(name:"922760") <= 0 ) exit(0); 
if ( hotfix_missing(name:"925454") <= 0 ) exit(0); 
if ( hotfix_missing(name:"928090") <= 0 ) exit(0); 
if ( hotfix_missing(name:"931768") <= 0 ) exit(0); 
if ( hotfix_missing(name:"933566") <= 0 ) exit(0); 


port = get_kb_item("SMB/transport");
if(!port) port = 139;


version = get_kb_item("SMB/IE/Version");
if (version && ereg(pattern:"^6\.0*\.2800\.1106", string:version))
{
 if (is_accessible_share())
 {
  if ( hotfix_is_vulnerable (os:"5.1", sp:1, file:"Browseui.dll", version:"6.0.2800.1584", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.0", file:"Browseui.dll", version:"6.0.2800.1584", dir:"\system32") || 
       hotfix_is_vulnerable (os:"4.0", file:"Browseui.dll", version:"6.0.2800.1584", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS04-040", value:TRUE);
 security_hole(get_kb_item("SMB/transport"));
 }
 
  hotfix_check_fversion_end(); 
  exit (0);
 }
 else
 {
  if ( hotfix_ie_gt(7) != 0 ) exit(0);
  key = get_kb_item ("SMB/Registry/HKLM/SOFTWARE/Microsoft/Active Setup/Installed Components/{839117ee-2132-4bae-a56a-42b50204c9b9}/Version");
  if (!key)
 {
 set_kb_item(name:"SMB/Missing/MS04-040", value:TRUE);
 security_hole(port);
 }
  else
    set_kb_item (name:"SMB/KB889293", value:TRUE);
 }
}
