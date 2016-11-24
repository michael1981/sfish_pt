#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(35076);

 script_cve_id("CVE-2008-4032");
 script_bugtraq_id(32638);
 script_xref(name:"OSVDB", value:"50585");
 
 script_version("$Revision: 1.6 $");

 script_name(english: "MS08-077: Vulnerability in Microsoft Office SharePoint Server Could Cause Elevation of Privilege (957175)");

 script_set_attribute(attribute:"synopsis", value:
"A user can elevate his privileges through SharePoint." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of SharePoint Server 2007 that
has a privilege elevation vulnerability in the SharePoint site. 

An attacker may use this to execute scripts in the context of the
SharePoint site." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for SharePoint Server 2007 :

http://www.microsoft.com/technet/security/bulletin/ms08-077.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
 summary["english"] = "Determines the version of SharePoint";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
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

path = NULL;

# Determine where it's installed.

key = "SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\12.0";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
 value = RegQueryValue(handle:key_h, item:"Location");
 if (!isnull(value))
   path = value[1];

 RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);
NetUseDel (close:FALSE);

if (!path)
{
 NetUseDel();
 exit(0);
}

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\BIN\Mssph.dll", string:path);


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
  # Version 12.0.6326.5000
  if ( v[0] == 12 && v[1] == 0 && v[2] < 6326 )
 {
 set_kb_item(name:"SMB/Missing/MS08-077", value:TRUE);
 hotfix_security_warning();
 }
 }
}


NetUseDel();
