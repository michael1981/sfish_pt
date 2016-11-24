#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24341);
  script_version("$Revision: 1.3 $");

  script_name(english:"uTorrent Detection");
  script_summary(english:"Checks for uTorrent"); 
 
 script_set_attribute(attribute:"synopsis", value:
"There is a peer-to-peer file sharing application installed on the
remote Windows host." );
 script_set_attribute(attribute:"description", value:
"uTorrent is installed on the remote Windows host.  uTorrent is a tiny,
BitTorrent client for peer-to-peer file sharing on Windows." );
 script_set_attribute(attribute:"see_also", value:"http://www.utorrent.com/" );
 script_set_attribute(attribute:"solution", value:
"Remove this software if its use does not match your corporate security
policy." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


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


# Find the path if it's installed.
path = NULL;
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\uTorrent";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"InstallLocation");
  if (!isnull(value)) path = value[1];

  RegCloseKey(handle:key_h);
}
if (isnull(path))
{
  key = "SOFTWARE\Classes\uTorrent\shell\open\command";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(value)) 
    {
      path = ereg_replace(pattern:'"(.+)\\\\uTorrent\\.exe".*', replace:"\1", string:value[1]);
    }

    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);


# If we have a path...
if (!isnull(path))
{
  report = string(
    "An unknown version of uTorrent is installed under :\n",
    "  ", path, "\n"
  );
  security_note(port:port, extra:report);
}


# Clean up.
NetUseDel();
