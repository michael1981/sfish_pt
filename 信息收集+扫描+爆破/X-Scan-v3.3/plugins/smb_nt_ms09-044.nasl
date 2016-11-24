# 
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(40565);
 script_version("$Revision: 1.1 $");

 script_cve_id("CVE-2009-1133", "CVE-2009-1929");
 script_bugtraq_id(35971, 35973);
 
 name["english"] = "MS09-044: Vulnerabilities in Remote Desktop Connection Could Allow Remote Code Execution (970927)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute arbitrary code on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Remote Desktop client with
several vulnerabilities that may allow an attacker to execute
arbirtary code on the remote host. 

To exploit these vulnerabilities, an attacker would need to lure
a user of the remote host to connect to a rogue RDP server.");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista and Server 2008 :

http://www.microsoft.com/technet/security/bulletin/ms09-044.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");

 script_set_attribute(
  attribute:"vuln_publication_date", 
  value:"2009/08/11"
 );
 script_set_attribute(
  attribute:"patch_publication_date", 
  value:"2009/08/11"
 );
 script_set_attribute(
  attribute:"plugin_publication_date", 
  value:"2009/08/11"
 );
 script_end_attributes();
 
 summary["english"] = "Checks for hotfix 970927";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
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

function win2k_get_path()
{
 local_var name, login, pass, domain, port, soc, r, hklm;
 local_var key, key_h, value, ret;

 ret = NULL;
 name    = kb_smb_name();
 login   = kb_smb_login(); 
 pass    = kb_smb_password();    
 domain  = kb_smb_domain();      
 port    = kb_smb_transport();

 if (!get_port_state(port)) exit(1, "SMB port is closed");
 soc = open_sock_tcp(port);
 if (!soc) exit(1, "Could not connect to the remote SMB port");

 session_init(socket:soc, hostname:name);
 r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
 if (r != 1) exit(1, "Could not log into the remote host");


 hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
 if (isnull(hklm))
 {
  NetUseDel();
  exit(1, "Could not open HKLM");
 }

 key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Terminal Server Client";
 key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
 if (!isnull(key_h))
 {
  value = RegQueryValue(handle:key_h, item:"UninstallString");
  if ( ! isnull(value) ) ret = value[1];
  RegCloseKey(handle:key_h);
 }
  RegCloseKey(handle:hklm);
 if ( ! isnull(ret) ) 
 	ret = ereg_replace(pattern:"\\setup\\Setup\.exe", string:ret, replace:"\");
  return ret;
}



if (!is_accessible_share()) exit(0);

if (hotfix_check_sp(win2k:6, xp:4, win2003:3, vista:3) > 0 )
{
 # Windows 2000
 if ( hotfix_check_sp(win2k:6) > 0 )
 { 
  path = win2k_get_path();
  if ( isnull(path) ) exit(0, "RDP Client not installed");
  if ( hotfix_is_vulnerable (os:"5.0", file:"Mstsc.exe", version:"5.1.2600.3552", path:path) ) 
  {
    hotfix_security_hole();
    set_kb_item(name:"SMB/Missing/MS09-044", value:TRUE);
    hotfix_check_fversion_end();
    exit (0);
  }
  exit(0, "Host is patched");
 }

 if ( 
      # MSRDP 6.0 and 6.1
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Mstscax.dll", version:"6.0.6000.16865", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:0, file:"Mstscax.dll", version:"6.0.6000.21061", min_version:"6.0.6000.21000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:1, file:"Mstscax.dll", version:"6.0.6001.18266", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:1, file:"Mstscax.dll", version:"6.0.6001.22443", min_version:"6.0.6001.22000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:2, file:"Mstscax.dll", version:"6.0.6002.18045", dir:"\system32") ||
      hotfix_is_vulnerable (os:"6.0", sp:2, file:"Mstscax.dll", version:"6.0.6002.22146", min_version:"6.0.6002.22000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", file:"Mstscax.dll", version:"6.0.6000.16865", min_version:"6.0.6000.16000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", file:"Mstscax.dll", version:"6.0.6001.18266", min_version:"6.0.6001.18000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", file:"Mstscax.dll", version:"6.0.6002.18045", min_version:"6.0.6002.18000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", file:"Mstscax.dll", version:"6.0.6000.16865", min_version:"6.0.6000.16000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", file:"Mstscax.dll", version:"6.0.6001.18266", min_version:"6.0.6001.18000", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", file:"Mstscax.dll", version:"6.0.6002.18045", min_version:"6.0.6002.18000", dir:"\system32") ||
     # MSRDP 5.2
      hotfix_is_vulnerable (os:"5.2", file:"Mstscax.dll",    version:"5.2.3790.4524", min_version:"5.2.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", file:"2k3Mstscax.dll", version:"5.2.3790.4524", min_version:"5.2.0.0", dir:"\system32") ||
     # MSRDP 5.1
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Mstscax.dll", version:"5.1.2600.3581", min_version:"5.1.0.0", dir:"\system32") )
  {
   set_kb_item(name:"SMB/Missing/MS09-044", value:TRUE);
   hotfix_security_hole();
   hotfix_check_fversion_end();
   exit(0);
  }

  hotfix_check_fversion_end();
  exit (0, "Host is patched");
}
