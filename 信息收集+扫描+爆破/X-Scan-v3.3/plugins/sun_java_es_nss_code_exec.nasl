#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25000);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-0008", "CVE-2007-0009");
  script_bugtraq_id(22694);
  script_xref(name:"OSVDB", value:"32105");
  script_xref(name:"OSVDB", value:"32106");

  script_name(english:"Sun Java Enterprise Server NSS Remote Code Execution Vulnerabilities");
  script_summary(english:"Checks version of JES' nss3.dll"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host uses a library that may allow remote code
execution." );
 script_set_attribute(attribute:"description", value:
"The version of Sun Java Enterprise Server (ES) installed on the remote
host includes a set of libraries known as Network Security Services
(NSS) for use with many of Java ES' services.  On a Windows host,
though, vulnerabilities in their implementation of SSL2 support
reportedly allow a remote attacker reportedly to execute arbitrary
code with LOCAL SYSTEM privileges." );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-26-102856-1" );
 script_set_attribute(attribute:"solution", value:
"Apply patch 125923-01." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
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
path = NULL;

key = "SOFTWARE\Sun Microsystems";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey) && subkey =~ "^Ent")
    {
      key2 = key + "\" + subkey + "\Installer";
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        value = RegQueryValue(handle:key2_h, item:"InstallPath");
        if (!isnull(value))
        {
          path = value[1];
          path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
        }
        RegCloseKey(handle:key2_h);
      }
    }
  }
  RegCloseKey (handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}


# Determine the version of nss3.dll.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\share\lib\nss3.dll", string:path);
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


# Check the version number.
if (!isnull(ver))
{
  fix = split("3.11.6.0", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      security_warning(port);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}


# Clean up.
NetUseDel();
