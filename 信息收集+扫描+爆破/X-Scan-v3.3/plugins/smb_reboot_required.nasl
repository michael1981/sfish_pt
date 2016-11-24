#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(35453);
  script_version("$Revision: 1.2 $");

  script_name(english:"Windows Reboot Required");
  script_summary(english:"Checks registry"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host requires a reboot." );
 script_set_attribute(attribute:"description", value:
"According to entries in its registry, a reboot is required by Windows
Update to complete installation of at least one update.  If the
pending changes are security-related, the remote host could remain
vulnerable to attack until a reboot occurs." );
 script_set_attribute(attribute:"solution", value:
"Reboot the remote system to put pending changes into effect." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");


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


# Check registry entries.
reboot = FALSE;

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[0]; ++i)
  {
    item = RegEnumValue(handle:key_h, index:i);
    if (!isnull(item) && item[1] =~ "^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$")
    {
      value = RegQueryValue(handle:key_h, item:item[1]);
      if (!isnull(value) && value[1] == 1)
      {
        reboot = TRUE;
        break;
      }
    }
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel();


if (reboot) security_hole(0);
