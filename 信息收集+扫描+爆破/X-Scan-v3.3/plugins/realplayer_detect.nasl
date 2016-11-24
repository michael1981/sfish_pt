#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20183);
  script_version("$Revision: 1.12 $");

  script_name(english:"RealPlayer Detection");
  script_summary(english:"Detects RealPlayer");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a media player installed on it." );
 script_set_attribute(attribute:"description", value:
"This script detects whether the remote Windows host is running
RealPlayer / RealOne Player / RealPlayer Enterprise and, if so,
extracts its version number. 

RealPlayer is a media player from RealNetworks." );
 script_set_attribute(attribute:"see_also", value:"http://www.real.com/" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("byte_func.inc");
include("smb_func.inc");
# for hex2dec
include("http_func.inc");


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


# Figure out where the executable is.
path = NULL;

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\RealPlay.exe";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(item))
  {
    path = item[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}


# Get the build and product name.
prod = NULL;
build = NULL;

hkcr = RegConnectRegistry(hkey:HKEY_CLASS_ROOT);
if (!isnull(hkcr))
{
  foreach appkey (make_list("RealPlayer", "RealOneEnt"))
  {
    key = "SOFTWARE\RealNetworks\" + appkey;
    key_h = RegOpenKey(handle:hkcr, key:key, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h))
    {
      info = RegQueryInfoKey(handle:key_h);
      for (i=0; i<info[1]; ++i)
      {
        subkey = RegEnumKey(handle:key_h, index:i);
        if (strlen(subkey) && subkey =~ "^[0-9]+\.")
        {
          key2 = key + "\" + subkey + "\Preferences\DisplayName";
          key2_h = RegOpenKey(handle:hkcr, key:key2, mode:MAXIMUM_ALLOWED);
          if (!isnull(key2_h))
          {
            item2 = RegQueryValue(handle:key2_h, item:NULL);
            if (!isnull(item2)) prod = item2[1];

            RegCloseKey(handle:key2_h);
          }

          key2 = key + "\" + subkey + "\Preferences\ClientLicenseKey";
          key2_h = RegOpenKey(handle:hkcr, key:key2, mode:MAXIMUM_ALLOWED);
          if (!isnull(key2_h))
          {
            item2 = RegQueryValue(handle:key2_h, item:NULL);
            if (!isnull(item2))
            {
              blob = item2[1];
              if (strlen(blob) > 19)
                build = hex2dec(xvalue:substr(blob, 12, 12)) + '.' +
                          hex2dec(xvalue:substr(blob, 13, 14)) + '.' +
                          hex2dec(xvalue:substr(blob, 15, 16)) + '.' +
                          hex2dec(xvalue:substr(blob, 17, 19));
            }
            RegCloseKey(handle:key2_h);
          }
        }
      }
      RegCloseKey(handle:key_h);
    }

    if (!isnull(build)) break;
  }
  RegCloseKey(handle:hkcr);
}


# Make sure the app is installed.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\realplay.exe", string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
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
if (isnull(fh))
{
  NetUseDel();
  exit(0);
}
CloseFile(handle:fh);


# Now get the version.
ui =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\rpplugins\rput3260.dll", string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:ui,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

version = NULL;
if (!isnull(fh))
{
  fsize = GetFileSize(handle:fh);

  chunk = 10240;
  ofs = fsize - chunk;
  while (ofs > 0 && ofs <= fsize)
  {
    data = ReadFile(handle:fh, length:chunk, offset:ofs);
    if (strlen(data) == 0) break;
    data = str_replace(find:raw_string(0), replace:"", string:data);
    if ("About %PRODUCT%" >< data)
    {
      about = strstr(data, "About %PRODUCT%") - "About %PRODUCT%";
      while (strlen(about) > 1)
      {
        len = getbyte(blob:about, pos:0);
        if (len > 1 && len < strlen(about))
        {
          info = substr(about, 1, len);
          if (info =~ "^Version [0-9]+\.[0-9.a-zA-Z]+$")
          {
            version = info - "Version ";
            break;
          }
          about = substr(about, len+1);
        }
        else break;
      }
    }
    if (isnull(version)) ofs -= chunk;
    else break;
  }
  CloseFile(handle:fh);
}


NetUseDel();


# If the build number's available, save and report it.
if (!isnull(build))
{
  if (isnull(prod)) prod = "unknown";
  if (isnull(version)) version = "unknown";

  set_kb_item(name:"SMB/RealPlayer/Build", value:build);
  set_kb_item(name:"SMB/RealPlayer/Version", value:version);
  set_kb_item(name:"SMB/RealPlayer/Product", value:prod);
  set_kb_item(name:"SMB/RealPlayer/Path", value:path);

  if (report_verbosity)
  {
    report = string(
      "\n",
      "  Product : ", prod, "\n",
      "  Version : ", version, "\n",
      "  Build   : ", build, "\n",
      "  Path    : ", path, "\n"
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
