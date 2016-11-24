#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25091);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-2151");
  script_bugtraq_id(23544);
  script_xref(name:"OSVDB", value:"34991");

  script_name(english:"McAfee E-Business Server Administration Client Length Remote DoS");
  script_summary(english:"Checks version of EBSAdmin.exe"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by a
denial of service vulnerability." );
 script_set_attribute(attribute:"description", value:
"McAfee E-Business Server, an enterprise tool for digitally encrypting
and signing electronic files, is installed on the remote host. 

The Administration Agent component of the version of McAfee E-Business
Server installed on the remote host reportedly fails to validate the
length from a packet header before using it to try to read input.  An
unauthenticated remote attacker may be able to leverage this issue to
crash the affected service, thereby denying service to legitimate
users." );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=516" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2007-04/0307.html" );
 script_set_attribute(attribute:"see_also", value:"https://knowledge.mcafee.com/article/780/612751_f.SAL_Public.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to e-Business Server 8.5.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
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


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Figure out where the installer recorded information about it.
list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (isnull(list)) exit(0);
key = NULL;
foreach name (keys(list))
{
  prod = list[name];
  if (prod && "McAfee E-Business Server" >< prod)
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
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}


# Determine the version of EBSAdmin.exe.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\EBSAdmin.exe", string:path);
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
    ver[0] < 8 ||
    (
      ver[0] == 8 &&
      (
        ver[1] < 1 ||
        (ver[1] == 1 && ver[2] < 1) ||
        (ver[1] == 5 && ver[2] < 2)
      )
    )
  )
  {
    version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);

    report = string(
      "\n",
      "Version ", version, " of the Administration Agent is installed as :\n",
      "\n",
      "  ", path, "\\EBSAdmin.exe", "\n"
    );
    security_warning(port:port, extra:report);
  }
}
