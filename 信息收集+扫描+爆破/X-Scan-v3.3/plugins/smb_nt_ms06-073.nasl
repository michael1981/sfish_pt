#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(23836);

 script_cve_id("CVE-2006-4704");
 script_bugtraq_id(20843);
 script_xref(name:"OSVDB", value:"30155");
 
 script_version("$Revision: 1.10 $");

 name["english"] = "MS06-073: Vulnerability in Visual Studio 2005 Could Allow Remote Code Execution (925674)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
browser." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Visual Studio 2005
which is vulnerable to a buffer overflow when handling malformed WMI
request in the ActiveX component. 

An attacker may exploit this flaw to execute arbitrary code on this
host, by entice a use to visit a specially crafter web page." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for VS2005 :

http://www.microsoft.com/technet/security/bulletin/ms06-073.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 summary["english"] = "Determines the version of visual studio";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");

 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

common = hotfix_get_commonfilesdir();
if ( ! common ) exit(1);

if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);
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


# Determine where it's installed.
key = "SOFTWARE\Microsoft\VisualStudio\8.0";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);


if (isnull(key_h))
{
 RegCloseKey(handle:hklm);
 NetUseDel();
 exit(0);
}
else
{
 RegCloseKey(handle:key_h);
 RegCloseKey(handle:hklm);
 NetUseDel (close:FALSE);
}

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:common);
wmi =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft Shared\WMI\wmiscriptutils.dll", string:common);


r = NetUseAdd(share:share);
if ( r != 1 ) 
{
 NetUseDel();
 exit(1);
}

handle = CreateFile (file:wmi, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

if ( ! isnull(handle) )
{
 v = GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if ( ! isnull(v) ) 
 {
  if ( v[0] == 8 && v[1] == 0 && ( (v[2] < 50727 ) || ( v[2] == 50727 && v[3] < 236 ) ) )
 {
 set_kb_item(name:"SMB/Missing/MS06-073", value:TRUE);
 hotfix_security_warning();
 }
 }
}


NetUseDel();
