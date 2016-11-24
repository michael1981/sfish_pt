#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(35611);
  script_version("$Revision: 1.4 $");
  
  script_bugtraq_id(33633);
  script_xref(name:"OSVDB", value:"51804");
  script_xref(name:"Secunia", value:"33805");

  script_name(english:"ESET Remote Administrator < 3.0.105 Additional Report Settings XSS");
  script_summary(english:"Checks version of era.exe");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by an
HTML injection vulnerability." );
 script_set_attribute(attribute:"description", value:
"ESET Remote Administrator is installed on the remote system.  The
installed version is less than version 3.0.105, and such versions are
reportedly affected by an HTML injection vulnerability.  An attacker
can exploit this vulnerability to cause arbitrary HTML and script code
to be executed with in the context of the user's browser." );
 script_set_attribute(attribute:"see_also", value:"http://www.eset.eu/support/changelog-eset-remote-administrator-3" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 3.0.105." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

#

include("smb_func.inc");
include("smb_hotfixes.inc");


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
if (rc != 1) {
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

# Find where it's installed.
path = NULL;

key = "SOFTWARE\ESET\ESET Remote Administrator\Server\CurrentVersion\Info";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"InstallDir");
  if (!isnull(value)) path = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0);
}

# Grab the file version of file era.exe

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\era.exe", string:path);

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
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}
NetUseDel();

# Check the version number.
if (!isnull(ver))
{
  fix = split("3.0.105", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity > 0)
      {
	version = string(ver[0],".",ver[1],".",ver[2]);
        report = string(
          "\n",
          "Version ", version, " of ESET Remote Administrator is installed under :\n",
          "\n",
          "  ", path, "\n"
        );
        security_warning(port:port, extra:report);
      }
      else	 
      	security_warning(port);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}
