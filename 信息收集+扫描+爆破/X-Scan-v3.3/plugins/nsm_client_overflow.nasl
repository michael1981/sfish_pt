#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(26922);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2007-5252");
  script_bugtraq_id(25932);
  script_xref(name:"OSVDB", value:"40588");

  script_name(english:"NetSupport NSM / NSS Initial Connection Setup Configuration Exchange Remote Overflow");
  script_summary(english:"Checks version of NSM's pcicl32.dll");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a program that is affected by a buffer
overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"NetSupport Manager (NSM), a multi-platform remote control application,
is installed on the remote host. 

According to its version, the NetSupport Manager client component on
the remote host fails to properly validate input during the initial
client connection sequence.  An unauthenticated remote attacker may be
able to leverage this issue to crash the affected service or possibly
execute arbitrary code.  [Note that the vendor has only acknowledged
the denial of service vulnerability.]" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/481537/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.netsupportsoftware.com/support/td.asp?td=545" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to NetSupport Manager version 10.20.0005 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );


script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");


# Figure out where the installer recorded information about it.
key = NULL;

list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (isnull(list)) exit(0);

foreach name (keys(list))
{
  prod = list[name];
  if (prod && "NetSupport Manager" >< prod)
  {
    key = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(.+)\/DisplayName$", replace:"\1", string:name);
    key = str_replace(find:"/", replace:"\", string:key);
    break;
  }
}
if (isnull(key)) exit(0);


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


# Find out where it was installed.
path = NULL;

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"InstallLocation");
  if (!isnull(item)) 
  {
    path = item[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  }

  RegCloseKey(handle:key_h);
}
if (isnull(path))
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  exit(0);
}


# Make sure it's a client install.
client = FALSE;

key = "SOFTWARE\NetSupport Manager\InstalledFeatures";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"client");
  if (!isnull(item) && 1 == item[1]) client = TRUE;
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (!client)
{
  NetUseDel();
  exit(0);
}


# Determine the version of PCICL32.DLL.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\PCICL32.DLL", string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:dll,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
ver = NULL;
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}
NetUseDel();


# Check the version number.
if (!isnull(ver))
{
  if (
    (ver[0] >= 9 && ver[0] < 10) ||
    (
      ver[0] == 10 &&
      (
        ver[1] < 20 ||
        (ver[1] == 20 && ver[2] < 5)
      )
    )
  )
  {
    if (ver[2] < 10) ver[2] = string("000", ver[2]);
    else if (ver[2] < 100) ver[2] = string("00", ver[2]);
    else if (ver[2] < 1000) ver[2] = string("0", ver[2]);
    version = string(ver[0], ".", ver[1], ".", ver[2]);

    report = string(
      "Version ", version, " of the NSM client is installed under :\n",
      "\n",
      "  ", path, "\n"
    );
    security_hole(port:port, extra:report);
  }
}
