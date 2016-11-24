#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(34121);
 script_version("$Revision: 1.4 $");

 script_cve_id("CVE-2008-3008");
 script_bugtraq_id(31065);
 script_xref(name:"OSVDB", value:"47962");
 
 script_name(english:"MS08-053: Vulnerability in Windows Media Encoder 9 Could Allow Remote Code Execution (954156)");
 script_summary(english:"Checks the version of Media Player");
 
 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "Arbitrary code can be executed on the remote host through Media\n",
   "Player."
  )
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote host is running Windows Media Player 9.\n",
   "\n",
   "There is a vulnerability in the remote version of this software hat\n",
   "may allow an attacker to execute arbitrary code on the remote host. \n",
   "\n",
   "To exploit this flaw, one attacker would need to set up a rogue web\n",
   "page and entice a victim to visit it."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Microsoft has released a set of patches for Windows 2000, XP, 2003,\n",
   "Vista and 2008 :\n",
   "\n",
   "http://www.microsoft.com/technet/security/bulletin/ms08-053.mspx"
  )
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();
 
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

name 	=  kb_smb_name();
login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();

path = NULL;

if(!get_port_state(port))exit(1);

soc = open_sock_tcp(port);
if(!soc)exit(1);

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(1);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) ) 
{
 NetUseDel();
 exit(0);
}


key = "Software\Microsoft\Windows Media\Encoder";
item = "InstallDir";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 value = RegQueryValue(handle:key_h, item:item);

 if (!isnull (value))
   path = value[1];

 RegCloseKey (handle:key_h);
}

RegCloseKey (handle:hklm);


NetUseDel();


if (path && is_accessible_share())
{
  if ( hotfix_is_vulnerable (os:"6.0", arch:"x86", file:"Wmex.dll", version:"9.0.0.3359", min_version:"9.0.0.0", path:path) ||
       hotfix_is_vulnerable (os:"6.0", arch:"x64", file:"Wmex.dll", version:"10.0.0.3817", min_version:"10.0.0.0", path:path) ||
       hotfix_is_vulnerable (os:"5.2", arch:"x86", file:"Wmex.dll", version:"9.0.0.3359", min_version:"9.0.0.0", path:path) ||
       hotfix_is_vulnerable (os:"5.2", arch:"x64", file:"Wmex.dll", version:"10.0.0.3817", min_version:"10.0.0.0", path:path) ||
       hotfix_is_vulnerable (os:"5.1", arch:"x86", file:"Wmex.dll", version:"9.0.0.3359", min_version:"9.0.0.0", path:path) ||
       hotfix_is_vulnerable (os:"5.0", arch:"x86", file:"Wmex.dll", version:"9.0.0.3359", min_version:"9.0.0.0", path:path) )
    hotfix_security_hole();

   hotfix_check_fversion_end(); 
}
