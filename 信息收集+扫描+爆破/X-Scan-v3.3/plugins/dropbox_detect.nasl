#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35717);
  script_version("$Revision: 1.1 $");

  script_name(english:"Dropbox Software Detection");
  script_summary(english:"Checks Windows Registry for Dropbox");

  script_set_attribute(attribute:"synopsis",value:
"There is a file synchronization application on the remote host.");
  script_set_attribute(attribute:"description",value:
"Dropbox is installed on the remote host.  Dropbox is an application
for storing and synchronizing files between computers, possibly
outside the organization.");
  script_set_attribute(attribute:"see_also",value:"https://www.getdropbox.com");

  script_set_attribute(attribute:"solution", value:
"Remove this software if its use does not match your organization's
security policy.");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139,445);

  exit(0);
}

include("smb_func.inc");


list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (isnull(list)) exit(0);

installstring = NULL;
foreach name (keys(list))
{
  prod = list[name];
  if (prod && "Dropbox" >< prod)
  {
    installstring = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(SOFTWARE\/Microsoft\/Windows\/CurrentVersion\/Uninstall\/.+)\/DisplayName$", replace:"\1", string:name);
    installstring = str_replace(find:"/", replace:"\", string:installstring);
    break;
  }
}

if(isnull(installstring)) exit(0);

# Connect to the appropriate share
name      = kb_smb_name();
port      = kb_smb_transport();
if (!get_port_state(port)) exit(0);
login     = kb_smb_login();
pass      = kb_smb_password();
domain    = kb_smb_domain();

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

dropbox_path = NULL;
key_h = RegOpenKey(handle:hklm, key:installstring, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"InstallLocation");
  if (!isnull(item))
  {
    dropbox_path = item[1];
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(dropbox_path))
{
 NetUseDel();
 exit(0);
}

ver = NULL;

# Determine the version from the executable.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:dropbox_path);
exe   = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Dropbox.exe", string:dropbox_path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if(rc != 1)
{
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

if (!isnull(fh))
{
  version = GetFileVersion(handle:fh);
  ver = string(version[0], ".", version[1], ".", version[2], ".", version[3]);
}


# Clean up.
NetUseDel();

if (ver)
{
  set_kb_item(name:"SMB/Dropbox/Path", value:dropbox_path);
  set_kb_item(name:"SMB/Dropbox/Version", value:ver);

  report = string(
    "\n",
    "  Version : ", ver, "\n",
    "  Path    : ", dropbox_path, "\n"
  );
  security_note(port:port, extra:report);
}
