#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(38948);
  script_version("$Revision: 1.2 $");

  script_name(english:"Soulseek Detection");
  script_summary(english:"Checks if Soulseek client is installed"); 
 
  script_set_attribute(
    attribute:"synopsis", 
    value:
"A file sharing application is installed on the remote host." );

  script_set_attribute(
    attribute:"description", 
    value:
"Soulseek, a peer-to-peer (P2P) file-sharing application is installed
on the remote system." );

  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.slsknet.org/" );

  script_set_attribute(
    attribute:"solution", 
    value:
"Make sure that use of this program agrees with your organization's
acceptable use and security policies." );

  script_set_attribute(
    attribute:"risk_factor", 
    value:
"None" );

  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");

# Figure out where the installer recorded information about it.

list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (isnull(list)) exit(0);

installstring = NULL;
foreach name (keys(list))
{
  prod = list[name];
  if (prod && ereg(pattern:"^SoulSeek [0-9]+", string:prod))
  {
   prod_ver = prod - "SoulSeek ";
   
   installstring = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(SOFTWARE\/Microsoft\/Windows\/CurrentVersion\/Uninstall\/.+)\/DisplayName$", replace:"\1", string:name);
   installstring = str_replace(find:"/", replace:"\", string:installstring);
   break;
  }
}

if(isnull(installstring)) exit(0);

# Get the install path

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

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}

key = installstring;
path = NULL;

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"UninstallString");
  if (!isnull(item))
    path = item[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (!path)
{
 NetUseDel();
 exit(0);
}

# nb :
#  - Do a sanity check to verify if slsk.exe exists.
#  - We don't rely on version from slsk.exe as it is not accurate.

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1", string:path);
exe  =  ereg_replace(pattern:"^[A-Za-z]:(.+)\\uninstall\.exe", replace:"\1slsk.exe", string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:string(share,"$"));
if (rc != 1)
{
 NetUseDel();
 exit(0);
}

fh = CreateFile(file:exe, 
	desired_access:GENERIC_READ, 
	file_attributes:FILE_ATTRIBUTE_NORMAL, 
	share_mode:FILE_SHARE_READ, 
	create_disposition:OPEN_EXISTING);

ver = NULL;
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}
	
NetUseDel();


if (!isnull(ver))
{
  path = string(share,":",exe);
  set_kb_item(name:"SMB/Soulseek/Path", value:path);
  set_kb_item(name:"SMB/Soulseek/Version", value:prod_ver);

  if (report_verbosity > 0)
  { 
    report = string(
      "\n",
      "  Product : Soulseek ","\n",
      "  Version : ", prod_ver, "\n",
      "  Path    : ", path, "\n"
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}       
