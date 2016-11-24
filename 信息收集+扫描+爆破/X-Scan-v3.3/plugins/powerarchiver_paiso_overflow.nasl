#
#  (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(23976);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2007-0097");
  script_bugtraq_id(21867);
  script_xref(name:"OSVDB", value:"32576");

  script_name(english:"PowerArchiver paiso.dll ISO Image Handling Buffer Overflow");
  script_summary(english:"Checks file versions of paiso.dll"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a library that is affected by a
buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host contains PowerArchiver, a file compression utility for
Windows. 

The version of PowerArchiver installed on the remote host has a buffer
overflow in the 'paiso.dll' library file that can be triggered when
processing the full pathname of a file within an ISO image.  If an
attacker can trick a user on the affected host into opening a
specially-crafted ISO image file, he can leverage this issue to
execute arbitrary code on the host subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://vuln.sg/powarc964-en.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2007-01/0101.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PowerArchiver 9.64.03 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
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


# Check whether it's installed.
exe = NULL;
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\POWERARC.EXE";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value)) exe = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(exe)) {
  NetUseDel();
  exit(0);
}


# Determine the version from the program itself.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:exe);
exe2 =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:exe);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:exe2,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
ver = NULL;
if (!isnull(fh)) {
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}


# Check the version number.
if (!isnull(ver))
{
  fix = split("9.6.4.3", sep:'.', keep:FALSE);
  for (i=0; i<4; i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      # nb: file version is slightly different from the software version.
      if (ver[3] < 10) ver[3] = string("0", ver[3]);
      version = string(ver[0], ".", ver[1], ver[2], ".", ver[3]);
      report = string(
        "Version ", version, " of PowerArchiver is installed as : \n",
        "\n",
        "  ", exe, "\n"
      );
      security_hole(port:port, extra:report);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}


# Clean up.
NetUseDel();
