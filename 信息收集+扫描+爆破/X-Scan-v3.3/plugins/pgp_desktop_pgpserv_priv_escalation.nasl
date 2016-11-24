#
#  (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(24246);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-0603");
  script_bugtraq_id(22247);
  script_xref(name:"OSVDB", value:"32969");
  script_xref(name:"OSVDB", value:"32970");

  script_name(english:"PGP Desktop PGPserv Crafted Data Object Arbitrary Code Execution");
  script_summary(english:"Checks version of PGP Desktop"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by a
privilege escalation issue." );
 script_set_attribute(attribute:"description", value:
"The version of PGP Desktop installed on the remote host reportedly can
allow a remote authenticated user to execute arbitrary code on the
affected host with LOCAL SYSTEM privileges.  The issue arises because
the software operates a service named 'PGPServ' or 'PGPsdkServ' that
exposes a named pipe that fails to validate the object data passed to
it." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eaff6760" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/458137/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PGP Desktop version 9.5.2 or later, as the change log
suggests the issue has been addressed in that version." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C" );
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


# Get some info about the install.
key = "SOFTWARE\PGP Corporation\PGP";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
path = NULL;
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"INSTALLPATH");
  if (!isnull(item)) path = item[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);


# If it is...
if (path)
{
  # Determine its version from the executable itself.
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\PGPdesk.exe", string:path);
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
    ver = GetFileVersion(handle:fh);
    CloseFile(handle:fh);
  }

  # There's a problem if the version is < 9.5.2.
  #
  # nb: the NGS advisory states it's been addressed in 9.5.1, but the 
  #     changelog suggests the fix was introduced in 9.5.2. 
  if (!isnull(ver))
  {
    fix = split("9.5.2.0", sep:'.', keep:FALSE);
    for (i=0; i<4; i++)
      fix[i] = int(fix[i]);

    for (i=0; i<max_index(ver); i++)
      if ((ver[i] < fix[i]))
      {
        version = string(ver[0], ".", ver[1], ".", ver[2], " [Build ", ver[3], "]");
        report = string(
          "PGP Desktop version ", version, " is installed under :\n",
          "\n",
          "  ", path
        );
        security_hole(port:port, extra:report);

        break;
      }
      else if (ver[i] > fix[i])
        break;
  }
}


# Clean up.
NetUseDel();
