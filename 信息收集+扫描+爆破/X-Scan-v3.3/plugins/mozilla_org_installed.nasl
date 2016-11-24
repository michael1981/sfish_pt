#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(20862);
  script_version("$Revision: 1.21 $");

  script_name(english:"Mozilla Foundation Application Detection");
  script_summary(english:"Checks for various applications from the Mozilla Foundation"); 
 
  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote Windows host contains one or more applications from the\n",
      "Mozilla Foundation."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "There is at least one instance of Firefox, Thunderbird, SeaMonkey, or\n",
      "the Mozilla browser installed on the remote Windows host."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/products/"
  );
  script_set_attribute(
    attribute:"solution",
    value:"n/a"
  );
  script_set_attribute(
    attribute:"risk_factor",
    value:"None"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
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


# Look in various registry hives for application info.
exes = make_array();
lcexes = make_array();

key = "SOFTWARE\Mozilla";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey) && subkey =~ "^(Mozilla|Mozilla Firefox|Mozilla Thunderbird|SeaMonkey) [0-9]+\.[0-9]+")
    {
      key2 = key + "\" + subkey + "\bin";
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        item = RegQueryValue(handle:key2_h, item:"PathToExe");
        if (!isnull(item)) 
        {
          file = item[1];
          if (!lcexes[tolower(file)])
          {
            exes[file] = subkey;
            lcexes[tolower(file)]++;
          }
        }
      }
    }
  }
  RegCloseKey (handle:key_h);
}
# nb: older versions seem to store info only under here.
apps = make_list(
  "Mozilla", 
  "Mozilla Firefox", 
  "Mozilla Thunderbird", 
  "SeaMonkey"
);
foreach app (apps)
{
  key = "SOFTWARE\mozilla.org\" + app;
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    info = RegQueryInfoKey(handle:key_h);
    for (i=0; i<info[1]; ++i)
    {
      subkey = RegEnumKey(handle:key_h, index:i);
      if (strlen(subkey) && subkey =~ "^[0-9]+\.[0-9]+")
      {
        key2 = key + "\" + subkey + "\Main";
        key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
        if (!isnull(key2_h))
        {
          item = RegQueryValue(handle:key2_h, item:"PathToExe");
          if (!isnull(item)) 
          {
            file = item[1];
            if (!lcexes[tolower(file)])
            {
              exes[file] = app + " " + subkey;
              lcexes[tolower(file)]++;
            }
          }
        }
      }
    }
  }
  RegCloseKey (handle:key_h);
}
RegCloseKey(handle:hklm);


# Determine the version of each app from each executable itself.
info = "";

foreach exe (keys(exes))
{
  # Determine its version from the executable itself.
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:exe);
  exe2 =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:exe);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1);
  }

  fh = CreateFile(
    file:exe2,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  ver = NULL;
  if (!isnull(fh))
  {
    filever = GetFileVersion(handle:fh);
    ret = GetFileVersionEx(handle:fh);
    CloseFile(handle:fh);

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
        if (!isnull(data))
        {
          ver = data['ProductVersion'];

          # hack - in some earlier versions of Firefox and Thunder bird, it
          # looks like they mistakenly swapped FileVersion and ProductVersion.
          # The minor version number of releases 1.x and after has been 0 or 5.
          # if the ProductVersion doesn't look right, go with FileVersion
          if (
            !isnull(ver) &&
            (data['ProductName'] == 'Firefox' || data['ProductName'] == 'Thunderbird') &&
            ereg(string:ver, pattern:'^[1-9].[1-46-9].')
          ) { ver = data['FileVersion']; }
        }
      }
    }

    if (!isnull(ver))
    {
      path = ereg_replace(pattern:"^(.+)\\[^\\]+$", replace:"\1", string:exe);

      prod = exes[exe];
      prod = ereg_replace(pattern:"^(.+) [0-9]+\..*$", replace:"\1", string:prod);

      if (!isnull(filever) && ver && ver =~ "^1\.[0-9]+.*\: 200[0-9]")
        ver = ver - strstr(ver, ":");

      kb_base = str_replace(find:" ", replace:"/", string:prod);
      save_version_in_kb(key:kb_base+"/Version", ver:ver);
      set_kb_item(name:"SMB/"+kb_base+"/"+ver, value:path);

      info += '  - ' + prod + ' version ' + ver + ' is installed under\n' +
              '    ' + path + '\n' +
              '\n';
    }
  }
}
NetUseDel();


if (info)
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      info
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
