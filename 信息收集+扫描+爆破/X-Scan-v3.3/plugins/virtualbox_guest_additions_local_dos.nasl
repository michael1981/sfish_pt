#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(42831);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(37024);
  script_xref(name:"Secunia", value:"37363");

  script_name(english:"Sun VirtualBox Guest Additions < 2.0.12 / 3.0.10 Local DoS");
  script_summary(english:"Checks version of Sun VirtualBox Guest Additions");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host is running a set of virtualization utilities
that is affected by a local denial of service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host is running a version of Sun VirtualBox Guest
Additions earlier than 2.0.12 or 3.0.10.  Such versions are potentially
affected by a local denial-of-service vulnerability."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-271149-1"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Sun VirtualBox Guest Additions 2.0.12, 3.0.10, or later.");
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/11/17"
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

name     = kb_smb_name();
port     = kb_smb_transport();
if (!get_port_state(port)) exit(0);
login    = kb_smb_login();
pass     = kb_smb_password();
domain   = kb_smb_domain();

soc = open_sock_tcp(port);
if (!soc) exit(1, "Can't open a socket on port " + port + ".");

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

path = NULL;

key = 'SOFTWARE\\Sun\\VirtualBox Guest Additions';
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
  exit(1, "Unable to find evidence of VirtualBox Guest Additions in the registry.");
}
NetUseDel(close:FALSE);

# Get the version info from VBoxDisp.dll.
share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:path);
dll = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\VBoxDisp.dll", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to '"+share+"' share.");
}

fh = CreateFile(
  file:dll,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (isnull(fh))
{
  NetUseDel();
  exit(1, "Could not access file " + dll + ".");
}

version = NULL;

#Grab the version info from VBoxDisp.dll
version = GetProductVersion(handle:fh);
CloseFile(handle:fh);
NetUseDel();

if (version)
{
  if (
    version =~ "^1\.6\." ||
    version =~ "^2\.(0\.([0-9]|10)[^0-9]|[12]\.)" ||
    version =~ "^3\.0\.[0-8][^0-9]"
  )
  {
    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "Path     : ", path, "\n",
        "Version  : ", version, "\n"
      );

      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
  else exit(0, "The remote host is not affected.");
}
else exit(1, "Error retrieving version number from VirtualBox Guest Additions file: " + dll);
