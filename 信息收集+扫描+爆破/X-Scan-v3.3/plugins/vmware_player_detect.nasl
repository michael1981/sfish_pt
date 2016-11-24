#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(31728);
  script_version("$Revision: 1.3 $");
  script_name(english:"VMware Player detection (Windows)");
  script_summary(english:"Checks version of VMware Player installed"); 
 
 script_set_attribute(attribute:"synopsis", value:
"An OS Virtualization application is installed on the remote host." );
 script_set_attribute(attribute:"description", value:
"VMware Player, a OS virtualization software that allows running virtual
machines created with VMware Workstation/Server on a Windows or Linux PC 
is installed on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/products/player/" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

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
  if (prod && "VMware Player" >< prod)
  {
   installstring = ereg_replace(pattern:"^(SMB\/Registry\/HKLM\/SOFTWARE\/Microsoft\/Windows\/CurrentVersion\/Uninstall\/.+)\/DisplayName$", replace:"\1", string:name);
   break;
  }
}

if(!isnull(installstring))
player_version = get_kb_item(string(installstring,"/","DisplayVersion"));

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

prod_ver  = NULL;
build_ver = NULL;
path	  = NULL;

key = "SOFTWARE\VMware, Inc.\VMware Player";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  # If VMware Player is installed...
  item = RegQueryValue(handle:key_h, item:"ProductVersion");
  if (!isnull(item))
  {
    prod_ver = item[1];
  }
  item = RegQueryValue(handle:key_h, item:"BuildNumber");
  if (!isnull(item))
  {
    build_ver = item[1];
  }
  item = RegQueryValue(handle:key_h, item:"InstallPath");
  if (!isnull(item))
  {
    path = item[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  }
  RegCloseKey(handle:key_h);
}

if(isnull(path))
{
 # Try another registry location known to include VM player
 # path info.
  
  key = "SOFTWARE\VMware, Inc.\VMware Workstation";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  { 
    item = RegQueryValue(handle:key_h, item:"InstallPath");
    if (!isnull(item))
     {
       path = item[1];
       if ("VMware Player" >< path)
       path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);

       RegCloseKey(handle:key_h);
     }
  }
} 

RegCloseKey(handle:hklm);

if (!path)
{
 NetUseDel();
 exit(0);
}

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\vmplayer.exe", string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
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

# VMware Player file version is not the same as the one indicated
# in the registry. For e.g at the time of writing this plugin the file
# version was 6.0.3 where as the registry correctly pointed to 
# the current version i.e. 2.0.3 with the build number. But we do sanity 
# check to make sure VMware player was not accidentally wiped
# off from hard drive, resulting in a false positive. If we can
# obtain ver, it is clear that the VMware player is installed and
# therefore we rely on registry for version info. 

if (isnull(ver)) exit(0);

if (isnull(prod_ver))
{
 prod_ver = player_version; # Version from installer entries.
 if(isnull(prod_ver)) exit(0);
} 

if (!isnull(prod_ver))
{
 set_kb_item(name:"VMware/Player/Version", value:prod_ver);
}
if(!isnull(build_ver))
{
 v = split(prod_ver,sep:".",keep:FALSE);
 build = string(v[0],".",v[1],".",v[2],".",build_ver);
 set_kb_item(name:"VMware/Player/BuildVersion", value:build);
}

if(report_verbosity)
{
 if (build_ver)
 {
  report = string(
          "\n",
          "VMware Player version ", prod_ver, " build (", build_ver,") is installed under :\n",
          "\n",
          "  ", path, "\n"
    );
 }
 else
 {
 report = string(
          "\n",
          "VMware Player version ", prod_ver, " is installed under :\n",
          "\n",
          "  ", path, "\n"
    );
 }
 security_note(port:port, extra:report);
}
else
 security_note(port:port);
