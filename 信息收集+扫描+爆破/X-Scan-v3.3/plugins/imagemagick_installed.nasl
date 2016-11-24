#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(38949);
  script_version("$Revision: 1.2 $");

  script_name(english:"ImageMagick Detection");
  script_summary(english:"Checks for ImageMagick installs");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an image editing application installed." );
  script_set_attribute(attribute:"description", value:
"The remote Windows host has ImageMagick installed. ImageMagick is an
application for creating, editing, and composing bitmap images." );
  script_set_attribute(attribute:"see_also", value:"http://www.imagemagick.org/script/index.php" );
  script_set_attribute(attribute:"solution", value:
"Check that the use of ImageMagick is in agreement with your
organization's security and acceptable use policies." );
  script_set_attribute(attribute:"risk_factor", value:"None" );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);

function display_dword (dword, nox)
{
  local_var tmp;
  
  if (isnull(nox) || (nox == FALSE))
    tmp = "0x";
  else
    tmp = "";

  return string (tmp,
                toupper(
                  hexstr(
                    raw_string(
                               (dword >>> 24) & 0xFF,
                               (dword >>> 16) & 0xFF,
                               (dword >>> 8) & 0xFF,
                               dword & 0xFF
                             )
                        )
                      )
                 );
}



# Connect to the appropriate share.
name    = kb_smb_name();
port    = kb_smb_transport();
if (!get_port_state(port)) exit(0);
login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();

soc = open_sock_tcp(port);
if (!soc) exit(0);

session_init(socket:soc, hostname:name);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

# Connect to the remote registry
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}

# Look through the registry for application info
paths = make_array();

key = "SOFTWARE\ImageMagick";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    prod = "ImageMagick";
    subkey = RegEnumKey(handle:key_h, index:i);
    prod = prod + " " + subkey;
    if (strlen(subkey) && subkey =~ "^([0-9\.]+)")
    {
      key2 = key + "\" + subkey;
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        info2 = RegQueryInfoKey(handle:key2_h);
        for (j=0; j<info2[1]; ++j)
        {
          subkey = RegEnumKey(handle:key2_h, index:j);
          prod = prod + " " + subkey;
          if (strlen(subkey) && subkey =~ "^Q:[0-9]+")
          {
            key3 = key2 + "\" + subkey;
            key3_h = RegOpenKey(handle:hklm, key:key3, mode:MAXIMUM_ALLOWED);
            if (!isnull(key3_h))
            {
              item = RegQueryValue(handle:key3_h, item:"BinPath");
              if (!isnull(item))
              {
                paths[prod] = item[1];
              }
              RegCloseKey(handle:key3_h);
            }
          }
        }
        RegCloseKey(handle:key2_h);
      }
    }
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);


# Check the file display.exe for version info.
info = "";
kb_base = "SMB/ImageMagick";
s = 0;

foreach prod (keys(paths))
{
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:paths[prod]);
  exe = ereg_replace(pattern:"[A-Za-z]:(.*)", replace:"\1\display.exe", string:paths[prod]);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1);
  }

  fh = CreateFile(
    file:exe,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  
  version = NULL;
  if (!isnull(fh))
  {
    ret = GetFileVersionEx(handle:fh);
    if (!isnull(ret)) children = ret['Children'];
    if (!isnull(children))
    {
      varfileinfo = children['VarFileInfo'];
      if (!isnull(varfileinfo))
      {
        translation =
          (get_word (blob:varfileinfo['Translation'], pos:0) << 16) +
          get_word (blob:varfileinfo['Translation'], pos:2);
        translation = tolower(display_dword(dword:translation, nox:TRUE));
      }
      stringfileinfo = children['StringFileInfo'];
      if (!isnull(stringfileinfo) && !isnull(translation))
      {
        data = stringfileinfo[translation];
        if (!isnull(data)) version = data['Comments'];
        else
        {
          data = stringfileinfo[toupper(translation)];
          if (!isnull(data)) version = data['Comments'];
        }
      }
    }
    CloseFile(handle:fh);
  }
  if (!isnull(version))
  {  
    matches = eregmatch(pattern:"(ImageMagick ([0-9\.-]+)).*", string:version);
    version = matches[1];
    set_kb_item(name:kb_base+"/"+version, value:paths[prod]);
    info = string(
      info, "\n",
      "  Version : ", version, "\n",
      "  Path    : ", paths[prod], "\n"
    );
    s++;
  }
}
NetUseDel();

if (info)
{
  set_kb_item(name:kb_base+"/Installed", value:TRUE);

  if (report_verbosity > 0)
  {
    if (s > 1)
      report = "The following versions of ImageMagick are";
    else
      report = "The following version of ImageMagick is";
    report = string(
      report, " installed on the remote\n",
      "host :",
      info,
      "\n"
    );
    security_note(port:port, extra:report);
  }
  else security_note(port:port);
}
