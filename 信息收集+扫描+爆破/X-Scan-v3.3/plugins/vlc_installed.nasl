#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31852);
  script_version("$Revision: 1.6 $");

  script_name(english:"VLC Media Player Detection");
  script_summary(english:"Checks for VLC");
 
 script_set_attribute(attribute:"synopsis", value:
"There is a media player installed on the remote Windows host." );
 script_set_attribute(attribute:"description", value:
"VideoLAN VLC Media Player, a free and portable media player, is
installed on the remote Windows host." );
 script_set_attribute(attribute:"see_also", value:"http://www.videolan.org/" );
 script_set_attribute(attribute:"solution", value:
"Remove this software if its use does not match your corporate security
policy." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Connect to the appropriate share.
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
if (rc != 1) {
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


# Check whether it's installed along with any of its plugins.
path = NULL;
plugins = make_array();
ver_reg = NULL;

key = "SOFTWARE\VideoLAN\VLC";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"InstallDir");
  if (isnull(item)) item = RegQueryValue(handle:key_h, item:"Install_Dir");
  if (!isnull(item)) path = item[1];

  item = RegQueryValue(handle:key_h, item:"Version");
  if (!isnull(item)) ver_reg = item[1];

  RegCloseKey(handle:key_h);
}

# - Firefox and friends.
key = "SOFTWARE\MozillaPlugins";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey) && subkey =~ "^@videolan\.org/vlc")
    {
      key2 = key + "\" + subkey;
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        item = RegQueryValue(handle:key2_h, item:"Path");
        if (!isnull(item))
        {
          file = item[1];
          plugins[file] = "Mozilla";
        }
        RegCloseKey(handle:key2_h);
      }
    }
  }
  RegCloseKey (handle:key_h);
}
# - ActiveX Control
key = "SOFTWARE\Classes\CLSID\{E23FE9C6-778E-49D4-B537-38FCDE4887D8}\InprocServer32";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(item))
  {
    file = item[1];
    plugins[file] = "ActiveX";
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}


# Determine versions from various files.
info = "";

files = make_list(path+"\vlc.exe");
if (max_index(keys(plugins))) files = make_list(files, keys(plugins));
foreach file (files)
{
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:file);
  file2 = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:file);
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
  ver = NULL;
  if (!isnull(fh))
  {
    ret = GetFileVersionEx(handle:fh);
    # nb: really old versions (eg, 0.4.6) don't support GetFileVersionEx()
    #     so just use the registry version.
    if (isnull(ret))
    {
      if (file =~ "\\vlc\.exe$" && ver_reg)
      {
        kbkey = "SMB/VLC";
        info += '\n' +
                '  - VLC Media Player :\n' +
                '    ' + file + ', ' + ver_reg + '\n';
        set_kb_item(name:kbkey+"/File", value:file);
        set_kb_item(name:kbkey+"/Version", value:ver_reg);
      }
    }
    if (!isnull(ret)) children = ret['Children'];
    if (!isnull(children))
    {
      # nb: there's a problem using children['Translation'] to index into 
      #     the StringFileInfo structure.
      stringfileinfo = children['StringFileInfo'];
      if (!isnull(stringfileinfo))
      {
        foreach key (keys(stringfileinfo))
        {
          data = stringfileinfo[key];
          if (!isnull(data))
          {
            ver = data['FileVersion'];
            if (!isnull(ver))
            {
              if (file =~ "\\vlc\.exe$")
              {
                # Need to distinguish between 0.8.6g/h as a special case.
                if ("0.8.6g" == ver && ver_reg =~ "^0\.8\.6[hi]") ver = ver_reg;

                kbkey = "SMB/VLC";
                info += '\n' +
                        '  - VLC Media Player :\n' +
                        '    ' + file + ', ' + ver + '\n';
              }
              else
              {
                variant = plugins[file];
                kbkey = "SMB/VLC/" + variant;

                info += '\n';
                if (variant == "Mozilla")
                {
                  info += '  - Mozilla plugin :\n';
                }
                else if (variant == "ActiveX")
                {
                  info += '  - ActiveX plugin :\n';
                }
                info += '    ' + file + ', ' + ver + '\n';
              }
              set_kb_item(name:kbkey+"/File", value:file);
              set_kb_item(name:kbkey+"/Version", value:ver);

              break;
            }
          }
        }
      }
    }
    CloseFile(handle:fh);
  }
  NetUseDel(close:FALSE);
}
NetUseDel();


# Report what we found.
if (info)
{
  set_kb_item(name:"SMB/VLC/installed" , value:TRUE);

  if (report_verbosity)
  {
    # nb: info already has a leading '\n'.
    report = string(
    "\n",
      "Nessus found the following VLC Media Player components installed on\n",
      "the remote host :\n",
      info
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
