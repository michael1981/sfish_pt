#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(34335);
  script_version("$Revision: 1.2 $");

  script_bugtraq_id(31485);

  script_name(english:"WinZip 11.x gdiplus.dll Unspecified Vulnerability");
  script_summary(english:"Checks the version of WinZip's gdiplus.dll");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by an
unspecified vulnerability." );
 script_set_attribute(attribute:"description", value:
"WinZip is installed on the remote host.  The installed version of
WinZip is older than 11.2 SR-1 (Build 8261).  Such versions are known
to ship with an old version of a Microsoft DLL file, 'gdiplus.dll'
that is affected by an unspecified vulnerability. 

Note that only WinZip versions 11.x on Windows 2000 systems use this
file and are thus affected by this issue." );
 script_set_attribute(attribute:"see_also", value:"http://update.winzip.com/wz112sr1.htm" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WinZip 11.2 SR-1 (Build 8261) or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "os_fingerprint.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");

if(report_paranoia < 2)
{
  os = get_kb_item("Host/OS");
  if (!os || "Microsoft Windows 2000" >!< os) exit(0);
}

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

path = NULL;

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\winzip32.exe";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
  # If WinZip is installed...
  item = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(item))
   {
     path = item[1];
     path = str_replace(string:path,find:'winzip32.exe',replace:"");
   }

  RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);

if (isnull(path))
{
 NetUseDel();
 exit(0);
}

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
dll   =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\gdiplus.dll", string:path);
exe   =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\WINZIP32.EXE", string:path);

NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
 NetUseDel();
 exit(0);
}

# Get the product version first...

fh = CreateFile(file:exe,
        desired_access:GENERIC_READ,
        file_attributes:FILE_ATTRIBUTE_NORMAL,
        share_mode:FILE_SHARE_READ,
        create_disposition:OPEN_EXISTING);

prod_ver = NULL;
if (!isnull(fh))
{
  ret = GetFileVersionEx(handle:fh);
  if (!isnull(ret)) children = ret['Children'];

  stringfileinfo = children['StringFileInfo'];
  if (!isnull(stringfileinfo))
  {
    foreach key (keys(stringfileinfo))
    {
      data = stringfileinfo[key];
      if (!isnull(data))
        prod_ver  = data['ProductVersion'];
    }
  }
  CloseFile(handle:fh);
}

if (!prod_ver || !ereg(pattern:"^11\.[0-2] *\([0-9]+\)$",string:prod_ver))
 {
  NetUseDel();
  exit(0);
 }

# Now get the dll version...

fh = CreateFile(file:dll, 
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

if(!isnull(ver))
{
  # Version of gdiplus.dll shipped with 
  # 11.2 SR-1 (Build 8261) == 5.1.3102.5581

  fix = split("5.1.3102.5581", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity)
      {
	version = string(ver[0], ".", ver[1], ".", ver[2], ".",ver[3]);
        report = string(
          "\n",
          "Version ", version, " of gdiplus.dll shipped with WinZip is installed under :\n", 
          "\n",
          "  ", path, "\n",
          "\n",
	  "Please upgrade to version gdiplus.dll version 5.1.3102.5581 (included with \n",
          "11.2 SR-1 Build 8261) or later.\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      break;
    }
    else if (ver[i] > fix[i])
      break;
} 
