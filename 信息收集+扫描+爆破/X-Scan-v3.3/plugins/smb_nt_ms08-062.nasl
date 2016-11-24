#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(34407);
 script_version("$Revision: 1.6 $");

 script_cve_id("CVE-2008-1446");
 script_bugtraq_id(31682);
 script_xref(name:"OSVDB", value:"49059");

 name["english"] = "MS08-062: Microsoft IIS IPP Service Unspecified Remote Overflow (953155)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute arbitrary code on the remote host via the internet 
printing service." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Windows which is vulnerable to a 
security flaw which may allow a remote user to execute arbitrary code on the
remote host via an integer overflow in the internet printing service." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003, Vista, 2008:

http://www.microsoft.com/technet/security/bulletin/ms08-062.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
 summary["english"] = "Make sure update 953155 has been installed on the remote host";

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


if ( hotfix_check_sp(xp:4, win2003:3, win2k:6, vista:2) <= 0 ) exit(0);

if ( hotfix_check_iis_installed() <= 0 ) exit(0);

name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if (!get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);

session_init(socket:soc, hostname:name);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) 
{
  NetUseDel();
  exit(0);
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm)) 
{
  NetUseDel();
  exit(0);
}


key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\OC Manager\Subcomponents";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
value = NULL;
if (!isnull(key_h)) 
{
value = RegQueryValue(handle:key_h, item:"inetprint");
RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);
NetUseDel();

if ( isnull(value) || value[1] == 0 ) exit(0);


if (is_accessible_share())
{
      if ( hotfix_is_vulnerable (os:"6.0", sp:1, file:"Win32k.sys", version:"6.0.6001.22241", min_version:"6.0.6001.20000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:1, file:"Win32spl.dll", version:"6.0.6001.18119", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Win32spl.dll", version:"6.0.6000.20893", min_version:"6.0.6000.20000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Win32spl.dll", version:"6.0.6000.16728", dir:"\system32") ||

      hotfix_is_vulnerable (os:"5.2", sp:2, file:"Win32spl.dll", version:"5.2.3790.4371", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Win32spl.dll", version:"5.2.3790.3208", dir:"\system32") ||

      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Win32spl.dll", version:"5.1.2600.3435", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:3, file:"Win32spl.dll", version:"5.1.2600.5664", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Win32spl.dll", version:"5.0.2195.7188", dir:"\system32") )
   	 {
 set_kb_item(name:"SMB/Missing/MS08-062", value:TRUE);
 hotfix_security_hole();
 }
 
 hotfix_check_fversion_end();
 exit (0);
}
