#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40548);
  script_version("$Revision: 1.1 $");

  script_name(english:"Sun xVM VirtualBox Detection");
  script_summary(english:"Checks for a VirtualBox install");

  script_set_attribute(
    attribute:"synopsis",
    value:"A virtualization application is installed on the remote Windows host."
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "Sun xVM VirtualBox, a free virtualization application, is installed\n",
      "on the remote host."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.virtualbox.org/"
  );
  script_set_attribute(
    attribute:"solution",
    value:"n/a"
  );
  script_set_attribute(
    attribute:"risk_factor",
    value:"None"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/08/11"
  );
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


#
# code execution begins here
#

if (!get_kb_item("SMB/Registry/Enumerated"))
  exit(1, "The registry wasn't enumerated.");

name    =  kb_smb_name();
port    =  kb_smb_transport();
if (!get_port_state(port)) exit(0);
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

soc = open_sock_tcp(port);
if (!soc) exit(1, "Can't open a socket.");

session_init(socket:soc, hostname:name);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to remote registry.");
}

key = 'SOFTWARE\\Sun\\xVM VirtualBox';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
  path = RegQueryValue(handle:key_h, item:"InstallDir");
  if (path) path = path[1];

  RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(1, "Unable to find evidence of VirtualBox in the registry.");
}
else NetUseDel(close:FALSE);

# Try to access VirtualBox.exe from the installation directory, in order
# to make sure it's actually installed where the registry thinks it is
share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:path);
exe = ereg_replace(
  pattern:'^[A-Za-z]:(.*)',
  replace:"\1\VirtualBox.exe",
  string:path
);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
 NetUseDel();
 exit(1, "Unable to access share: " + share);
}

fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

# Grab the version number if the file was opened successfully.  Otherwise,
# bail out.
ver = NULL;
if (fh)
{
  ver = GetProductVersion(handle:fh);
  CloseFile(handle:fh);
  NetUseDel();
}
else
{
  NetUseDel();
  exit(1, "Unable to access VirtualBox file: " + exe);
}

if (ver)
{
  set_kb_item(name:"VirtualBox/Version", value:ver);
  set_kb_item(name:"SMB/VirtualBox/" + ver, value:path);

  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "Path    : ", path, "\n",
      "Version : ", ver, "\n"
    );

    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else exit(1, "Error retrieving version number from VirtualBox file: " + exe);
