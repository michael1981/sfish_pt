#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(26022);

 script_cve_id("CVE-2006-6133");
 script_bugtraq_id(21261);
 script_xref(name:"OSVDB", value:"31704");
 
 script_version("$Revision: 1.8 $");

 name["english"] = "MS07-052: Vulnerability in Crystal Reports for Visual Studio Could Allow Remote Code Execution (941522)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Visual
Studio." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Visual Studio that
may allow arbitrary code to be run. 

An attacker may use this to execute arbitrary code on this host. 

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have it open it.  Then a bug in the RPT
parsing handler would result in code execution." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Visual Studio 2002, 2003
and 2005 :

http://www.microsoft.com/technet/security/bulletin/ms07-052.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Determines the version of visual studio";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
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

path = vs = NULL;

# Determine where it's installed.

key = "SOFTWARE\Microsoft\VisualStudio\8.0\Packages\{97358C99-E52D-42C7-8B7C-B59CC4425F4B}";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
 vs = "8.0";
}
else
{
 key = "SOFTWARE\Microsoft\VisualStudio\7.1\Packages\{A9D28E15-E2CD-4185-A9BE-7DC617936ACB}";
 key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
 if (!isnull(key_h))
 {
  vs = "7.1";
 }
 else
 {
  key = "SOFTWARE\Microsoft\VisualStudio\7.0\Packages\{F05E92C6-8346-11D3-B4AD-00A0C9B04E7B}";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
   vs = "7.0";
  }
 }
}


if (!isnull(key_h))
{
 value = RegQueryValue(handle:key_h, item:"InprocServer32");
 if (!isnull(value))
   path = value[1];

 RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);
NetUseDel (close:FALSE);

if (!path || !vs)
{
 NetUseDel();
 exit(0);
}

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:path);


r = NetUseAdd(share:share);
if ( r != 1 ) 
{
 NetUseDel();
 exit(1);
}

handle = CreateFile (file:dll, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

if ( ! isnull(handle) )
{
 v = GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if ( ! isnull(v) ) 
 {
  if ( ( (vs == "8.0") && (v[0] == 10 && v[1] == 2 && v[2] == 0 && v[3] < 1222) ) ||
       ( (vs == "7.1") && ( (v[0] == 9 && v[1] < 1) || (v[0] == 9 && v[1] == 1 && v[2] < 2) || (v[0] == 9 && v[1] == 1 && v[2] == 2 && v[3] < 1871) ) ) ||
       ( (vs == "7.0") && ( (v[0] == 9 && v[1] < 1) || (v[0] == 9 && v[1] == 1 && v[2] == 0 && v[3] < 2004) ) ) )
 {
 set_kb_item(name:"SMB/Missing/MS07-052", value:TRUE);
 hotfix_security_hole();
 }
 }
}


NetUseDel();
