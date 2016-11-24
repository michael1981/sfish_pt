#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31651);
  script_version("$Revision: 1.3 $");

  script_name(english:"Orb Detection");
  script_summary(english:"Checks for Orb install");
 
 script_set_attribute(attribute:"synopsis", value:
"There is a peer-to-peer file sharing application installed on the
remote Windows host." );
 script_set_attribute(attribute:"description", value:
"Orb is installed on the remote Windows host.  Orb is a peer-to- peer
file sharing application for 'mycasting' digital content from a PC." );
 script_set_attribute(attribute:"see_also", value:"http://www.orb.com/" );
 script_set_attribute(attribute:"solution", value:
"Make sure use of this program fits with your corporate security
policy." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


include("global_settings.inc");
include("smb_func.inc");


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


# Make sure it's installed.
path = NULL;
ver = NULL;

key = "SOFTWARE\Orb Networks\Orb";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"InstallDir");
  if (!isnull(item)) 
  {
    path = item[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  }

  item = RegQueryValue(handle:key_h, item:"Version");
  if (!isnull(item)) ver = item[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}


# Make sure the main exe exists.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\bin\Orb.exe", string:path);
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
if (!isnull(fh))
{
  CloseFile(handle:fh);

  # Record some info in the KB and report it.
  set_kb_item(name:"SMB/Orb/Path",    value:path);
  if (isnull(ver)) ver = "unknown";
  set_kb_item(name:"SMB/Orb/Version", value:ver);

  if (report_verbosity)
  {
    report = string(
      "\n",
      "  Path    : ", path, "\n",
      "  Version : ", ver, "\n"
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
NetUseDel();
