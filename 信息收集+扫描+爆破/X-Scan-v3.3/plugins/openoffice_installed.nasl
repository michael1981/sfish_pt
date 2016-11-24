#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(25551);
  script_version("$Revision: 1.9 $");

  script_name(english:"OpenOffice Detection");
  script_summary(english:"Checks for OpenOffice"); 
 
  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Windows host contains an alternative office suite."
  );
  script_set_attribute(
    attribute:"description", 
    value:"OpenOffice is installed on the remote host."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openoffice.org/"
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

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
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
buildid = NULL;
ooo = FALSE;
path = NULL;

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\soffice.exe";
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
if (isnull(path))
{
  # Try to get it from Sun's property sheet handler.
  key = "SOFTWARE\Classes\CLSID\{63542C48-9552-494A-84F7-73AA6A7C99C1}\InprocServer32";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(item)) 
    {
      path = item[1];
      # nb: the value is sometimes wrapped in quotes.
      path = ereg_replace(pattern:'^"(.+)"$', replace:"\1", string:path);
      path = ereg_replace(pattern:"^(.+)\\program\\shlxthdl\.dll$", replace:"\1", string:path);
    }
    RegCloseKey(handle:key_h);
  }
}

RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}


# Determine the version of the file.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
cfg =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\program\version.ini", string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:cfg,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (isnull(fh))
{
  # Version 1.x stores info in a different file.
  cfg =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\program\bootstrap.ini", string:path);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(0);
  }

  fh = CreateFile(
    file:cfg,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
}
if (!isnull(fh))
{
  # nb: limit how much we'll read.
  fsize = GetFileSize(handle:fh);
  if (fsize > 1000) fsize = 1000;

  chunk = 1024;
  ofs = 0 ;

  while (fsize > 0 && ofs <= fsize)
  {
    data = ReadFile(handle:fh, length:chunk, offset:ofs);
    if (strlen(data) == 0) break;
    data = str_replace(find:raw_string(0), replace:"", string:data);
    if ("OpenOffice.org" >< data || "openoffice.org" >< data) ooo = TRUE;
    if ("buildid" >< data)
      buildid = ereg_replace(pattern:"^.+buildid *= *([0-9]+[a-z][0-9]+\(Build:[0-9]+\)).*", replace:"\1", string:data);
    if (isnull(buildid)) ofs += chunk;
    else break;
  }
  CloseFile(handle:fh);
}
NetUseDel();


# Save and report the version number and installation path.
if (ooo && !isnull(buildid) && !isnull(path))
{
  # Map build to a more user-friendly version number.
  vers[9420] = "3.1.1";
  vers[9399] = "3.1.0";
  vers[9379] = "3.0.1";
  vers[9358] = "3.0.0";
  vers[9364] = "2.4.2";
  vers[9310] = "2.4.1";
  vers[9286] = "2.4";
  vers[9238] = "2.3.1";
  vers[9221] = "2.3";
  vers[9161] = "2.2.1";
  vers[9134] = "2.2";
  vers[9073] = "2.0.4";
  vers[9044] = "2.0.3";
  vers[8950] = "1.1.5";

  set_kb_item(name:"SMB/OpenOffice/Path", value:path);
  set_kb_item(name:"SMB/OpenOffice/Build", value:buildid);

  ver = "build " + buildid;
  matches = eregmatch(pattern:"([0-9]+[a-z][0-9]+)\(Build:([0-9]+)\)", string:buildid);
  if (!isnull(matches))
  {
    prod = matches[1];
    build = int(matches[2]);
    if (build && vers[build]) ver = string("version ", vers[build], " (", prod, " / build ", build, ")");
  }

  report = string(
    "\n",
    "OpenOffice ", ver, " is installed under :\n",
    "\n",
    "  ", path
  );
  security_note(port:port, extra:report);
}
