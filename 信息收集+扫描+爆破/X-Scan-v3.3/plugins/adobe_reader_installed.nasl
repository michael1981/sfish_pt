#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(20836);
  script_version("$Revision: 1.13 $");

  script_name(english:"Adobe Reader Detection");
  script_summary(english:"Checks for Adobe Reader"); 
 
 script_set_attribute(attribute:"synopsis", value:
"There is a PDF file viewer installed on the remote Windows host." );
 script_set_attribute(attribute:"description", value:
"Adobe Reader, a PDF file viewer, is installed on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/products/acrobat/readermain.html" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");


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


# Determine where it's installed.
path = NULL;
min = NULL;
max = NULL;

# - nb: this works for recent versions of Adobe Reader.
key = "SOFTWARE\Adobe\Acrobat Reader";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey) && subkey =~ "^[0-9.]+$")
    {
      key2 = key + "\" + subkey + "\Installer";
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        value = RegQueryValue(handle:key2_h, item:"VersionMax");
        if (!isnull(value)) max = int(value[1]);

        value = RegQueryValue(handle:key2_h, item:"VersionMin");
        if (!isnull(value)) min = int(value[1]);

        value = RegQueryValue(handle:key2_h, item:"Path");
        if (!isnull(value)) path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:value[1]);

        RegCloseKey(handle:key2_h);
      }
    }
  }
  RegCloseKey (handle:key_h);
}
# - nb: this works for Acrobat Reader 5.x
if (isnull(path))
{
  key = "SOFTWARE\Classes\Software\Adobe\Acrobat\Exe";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(value)) 
    {
      # nb: the value may appear in quotes.
      exe = ereg_replace(pattern:'^"(.+)"', replace:"\1", string:value[1]);
      if ("AcroRd32" >< exe) path = exe - "\Reader\AcroRd32.exe";
    }

    RegCloseKey (handle:key_h);
  }
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}


# Determine its version from the executable itself.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Reader\AcroRd32.exe", string:path);

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
      translation = toupper(display_dword(dword:translation, nox:TRUE));
    }
    stringfileinfo = children['StringFileInfo'];
    if (!isnull(stringfileinfo) && !isnull(translation))
    {
      data = stringfileinfo[translation];
      if (!isnull(data)) version = data['ProductVersion'];
    }
  }
  CloseFile(handle:fh);
}


# Get the version from AcroRd32.dll for versions 7.x and 8.1.x.
if (version =~ "^(7\.0\.8\.|8\.1\.0\.)")
{
  dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Reader\AcroRd32.dll", string:path);
  fh = CreateFile(
    file:dll,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  version = "";
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
        translation = toupper(display_dword(dword:translation, nox:TRUE));
      }
      stringfileinfo = children['StringFileInfo'];
      if (!isnull(stringfileinfo) && !isnull(translation))
      {
        data = stringfileinfo[translation];
        if (!isnull(data)) version = data['ProductVersion'];
      }
    }
    CloseFile(handle:fh);
  }
}
NetUseDel();


# Save and report the version number and installation path.
if (!isnull(version) && !isnull(path))
{
  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  # Handle version changes in updates.
  if (!isnull(max) && !isnull(min))
  {
    a = (max >> 16);
    b = max & 0xffff;
    c = min >> 16;
    d = min & 0xffff;

    if (ver[0] > 7 && ver[0] == a && ver[1] == b && ver[2] < c)
    {
      ver[2] = c;
      ver[3] = d;
      version = string(ver[0], ".", ver[1], ".", ver[2]);
    }
    if (ver[0] <= 7 && a == 0 && ver[0] == b && ver[1] == c && ver[2] < d)
    {
      ver[2] = d;
      ver[3] = 0;
      version = string(ver[0], ".", ver[1], ".", ver[2]);
    }
  }

  # Reformat the version based on how it's displayed in 
  # the Help, About menu pull-down.
  pat = "^([0-9]+\.[0-9]+\.[0-9])\.(2[0-9]{3})([0-9]{2})([0-9]{2})([0-9]{2})$";
  v = eregmatch(pattern:pat, string:version);
  if (!isnull(v))
  {
    if (ver[0] < 7)
    {
      version_ui = string(v[1], " ", int(v[3]), "/", int(v[4]), "/", int(v[2]));
    }
    else
    {
      version_ui = v[1];
    }
  }
  else version_ui = version;

  set_kb_item(name:"SMB/Acroread/Path", value:path);
  set_kb_item(name:"SMB/Acroread/Version", value:version);
  set_kb_item(name:"SMB/Acroread/Version_UI", value:version_ui);

  report = string(
    "\n",
    "Nessus discovered the following installation of Adobe Reader :\n",
    "\n",
    "  Path    : ", path, "\n",
    "  Version : ", version_ui, "\n"
  );

  security_note(port:port, extra:report);
}
