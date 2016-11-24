#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(28211);
  script_version("$Revision: 1.7 $");

  script_name(english:"Flash Player Detection");
  script_summary(english:"Checks for Flash Player"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a browser enhancement for displaying
multimedia content." );
 script_set_attribute(attribute:"description", value:
"There is at least one instance of Adobe Flash Player installed on the
remote Windows host." );
 script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/products/flashplayer/" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );


script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "opera_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");


# Connect to the appropriate share.
if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);
name    =  kb_smb_name();
port    =  kb_smb_transport();
if (!get_port_state(port)) exit(0);
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

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


# Check whether it's installed.
variants = make_array();

# - check for the browser plugin.
key = "SOFTWARE\MozillaPlugins\@adobe.com/FlashPlayer";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(item))
  {
    file = item[1];
    variants[file] = "Plugin";
  }
  RegCloseKey(handle:key_h);
}
key = "SOFTWARE\Mozilla";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey) && subkey =~ "^Mozilla Firefox ")
    {
      key2 = key + "\" + subkey + "\Extensions";
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        item = RegQueryValue(handle:key2_h, item:"Plugins");
        if (!isnull(item))
        {
          file = item[1] + "\NPSWF32.dll";
          variants[file] = "Plugin";
        }
        RegCloseKey(handle:key2_h);
      }
    }
  }
  RegCloseKey(handle:key_h);
}
opera_path = get_kb_item("SMB/Opera/Path");
if (!isnull(opera_path))
{
  # nb: we'll check later whether this actually exists.
  file = opera_path + "\Program\Plugins\NPSWF32.dll";
  variants[file] = "Plugin";
}
# - check for the ActiveX control.
key = "SOFTWARE\Classes\CLSID\{D27CDB6E-AE6D-11cf-96B8-444553540000}\InprocServer32";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(item))
  {
    file = item[1];
    variants[file] = "ActiveX";
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (max_index(keys(variants)) == 0)
{
  NetUseDel();
  exit(0);
}


# Determine the version of each instance found.
counts["Plugin"] = 0;
counts["ActiveX"] = 0;
info = "";

foreach file (keys(variants))
{
  variant = variants[file];

  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:file);
  file2 =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:file);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(0);
  }

  fh = CreateFile(
    file:file2,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    ver = GetFileVersion(handle:fh);
    if (!isnull(ver))
    {
      counts[variant]++;
      version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);

      if (variant == "Plugin")
      {
        info += '  - Browser Plugin (for Firefox / Netscape / Opera) :\n';
      }
      else if (variant == "ActiveX")
      {
        info += '  - ActiveX control (for Internet Explorer) :\n';
      }

      info += '    ' + file + ', ' + version + '\n';

      set_kb_item(name:"SMB/Flash_Player/"+variant+"/File/"+counts[variant], value:file);
      set_kb_item(name:"SMB/Flash_Player/"+variant+"/Version/"+counts[variant] , value:version);
    }
    CloseFile(handle:fh);
  }
  NetUseDel(close:FALSE);
}
NetUseDel();


# Issue a report.
if (info)
{
  set_kb_item(name:"SMB/Flash_Player/installed" , value:TRUE);

  report = string(
    "Nessus found the following instances of Flash Player installed on the\n",
    "remote host :\n",
    "\n",
    info
  );
  security_note(port:kb_smb_transport(), extra:report);
}
