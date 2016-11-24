#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(34120);
 script_version("$Revision: 1.8 $");

 script_cve_id("CVE-2007-5348", "CVE-2008-3012", "CVE-2008-3013", "CVE-2008-3014", "CVE-2008-3015");
 script_bugtraq_id(31018, 31019, 31020, 31021, 31022);
 script_xref(name:"OSVDB", value:"47965");

 script_name(english:"MS08-052: Vulnerabilities in GDI+ Could Allow Remote Code Execution (954593)");
 script_summary(english:"Determines the presence of update 954593");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the Microsoft
GDI rendering engine." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows that has multiple
buffer oveflow vulnerabilities when viewing VML, EMF, GIF, WMF and BMP
files, which may allow an attacker to execute arbitrary code on the
remote host. 

To exploit this flaw, an attacker would need to send a malformed image
file to a user on the remote host and wait for him to open it using an
affected Microsoft application." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista and 2008 :

http://www.microsoft.com/technet/security/bulletin/ms08-052.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl", "mssql_version.nasl", "smb_nt_ms02-031.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

patched = 0;

rootfile = hotfix_get_systemroot();
if ( ! rootfile ) exit(1);


share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
path = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:rootfile);

name 	=  kb_smb_name();
login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();

if(!get_port_state(port))exit(1);

soc = open_sock_tcp(port);
if(!soc)exit(1);

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 ) exit(1);

paths = make_list (
      "\WinSxS\Policies\x86_policy.1.0.Microsoft.Windows.GdiPlus_6595b64144ccf1df_x-ww_4e8510ac",
      "\WinSxS\Policies\amd64_policy.1.0.Microsoft.Windows.GdiPlus_6595b64144ccf1df_x-ww_AE43B2CC"
      );

foreach spath (paths)
{
 spath = path + spath;
 handle =  CreateFile (file:spath, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_DIRECTORY, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
 if ( ! isnull(handle) )
 {
  patched++;
  CloseFile(handle:handle);
  break;
 }
}

NetUseDel();


vuln = 0;
office_version = hotfix_check_office_version ();
visio_version = get_kb_item("SMB/Office/Visio");
sqlpath = get_kb_item("mssql/path");

cdir = hotfix_get_commonfilesdir();

if (is_accessible_share())
{
 # Windows 2000, XP, 2003, Vista, 2008 and IE 6
 if ( !patched &&
    ( hotfix_is_vulnerable (os:"6.0", sp:0, file:"Gdiplus.dll", version:"5.2.6000.16683", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Gdiplus.dll", version:"5.2.6000.20826", min_version:"5.2.6000.20000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Gdiplus.dll", version:"6.0.6000.16683", min_version:"6.0.6000.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Gdiplus.dll", version:"6.0.6000.20826", min_version:"6.0.6000.20000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:1, file:"Gdiplus.dll", version:"5.2.6001.18065", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:1, file:"Gdiplus.dll", version:"5.2.6001.22170", min_version:"5.2.6001.20000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:1, file:"Gdiplus.dll", version:"6.0.6001.18065", min_version:"6.0.6001.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:1, file:"Gdiplus.dll", version:"6.0.6001.22170", min_version:"6.0.6001.20000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Gdiplus.dll", version:"5.2.3790.3126", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:2, file:"Gdiplus.dll", version:"5.2.3790.4278", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Gdiplus.dll", version:"5.1.3102.3352", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:3, file:"Gdiplus.dll", version:"5.1.3102.5581", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Gdiplus.dll", version:"5.1.3102.3352", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Vgx.dll", version:"6.0.2800.1612", min_version:"6.0.0.0", dir:"\Microsoft Shared\VGX", path:cdir) )
    )
 {
 {
 set_kb_item(name:"SMB/Missing/MS08-052", value:TRUE);
 hotfix_security_hole();
 }
  vuln++;
 }
 
 # Office 2003
 if (!vuln && "11.0" >< office_version)
 {
  path = hotfix_get_officeprogramfilesdir() + "\Microsoft Office\OFFICE11";

  if ( hotfix_check_fversion(file:"Gdiplus.dll", version:"11.0.8230.0", path:path) == HCF_OLDER )
  {
 {
 set_kb_item(name:"SMB/Missing/MS08-052", value:TRUE);
 hotfix_security_hole();
 }
   vuln++;
  }
 }
 
 # Office 2007
 if (!vuln && "12.0" >< office_version)
 {
  path = hotfix_get_commonfilesdir() + "\Microsoft Shared\OFFICE12";

  if ( hotfix_check_fversion(file:"Ogl.dll", version:"12.0.6325.5000", path:path) == HCF_OLDER )
  {
 {
 set_kb_item(name:"SMB/Missing/MS08-052", value:TRUE);
 hotfix_security_hole();
 }
   vuln++;
  }
 }

 # Visio 2002
 if (!vuln && "10.0" >< visio_version)
 {
  path = hotfix_get_commonfilesdir() + "\Microsoft Shared\OFFICE10";

  if ( hotfix_check_fversion(file:"Mso.dll", version:"10.0.6844.0", path:path) == HCF_OLDER )
  {
 {
 set_kb_item(name:"SMB/Missing/MS08-052", value:TRUE);
 hotfix_security_hole();
 }
   vuln++;
  }
 }

 # SQL server 2005
 if (!vuln)
 {
  if ( ( hotfix_check_fversion(path:rootfile, file:"Sqlservr.exe", version:"2005.90.3073.0", min_version:"2005.90.3000.0") == HCF_OLDER ) ||
     ( hotfix_check_fversion(path:rootfile, file:"Sqlservr.exe", version:"2005.90.3282.0", min_version:"2005.90.3200.0") == HCF_OLDER ) )
  {
 {
 set_kb_item(name:"SMB/Missing/MS08-052", value:TRUE);
 hotfix_security_hole();
 }
   vuln++;
  }
 }

 hotfix_check_fversion_end(); 
}

