#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40820);
  script_version("$Revision: 1.2 $");

  script_name(english:"Cerberus FTP Server Detection");
  script_summary(english:"Checks if Cerberus FTP is installed");

  script_set_attribute(
    attribute:"synopsis",
    value:"An FTP server is installed on the remote Windows host."
  );
  script_set_attribute(
    attribute:"description",
    value:"Cerberus FTP server is installed on the remote host."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.cerberusftp.com/"
  );
  script_set_attribute(
    attribute:"solution",
    value:"n/a"
  );
  script_set_attribute(
    attribute:"risk_factor",
    value:"None"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/08/31"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

#

include("misc_func.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");


#
# code execution begins here
#

if (!get_kb_item("SMB/Registry/Enumerated"))
  exit(1, "The registry wasn't enumerated.");

name    =  kb_smb_name();
port    =  kb_smb_transport();
if (!get_port_state(port)) exit(0);
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

soc = open_sock_tcp(port);
if (!soc) exit(1, "Error creating a socket on with dest port " + port);

session_init(socket:soc, hostname:name);

# The installer doesn't put any installation info in HKLM\software, so
# we'll check the default install path for 3.x
path = hotfix_get_programfilesdir();
if (!path) exit(1, "Can't determine Program Files directory.");
else path += "\Cerberus LLC\Cerberus FTP Server";

share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:path);
exe = ereg_replace(
  pattern:'^[A-Za-z]:(.*)',
  replace:"\1\CerberusGUI.exe",
  string:path
);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
 NetUseDel();
 exit(1, "Unable to access share: " + share);
}

fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

# Grab the version number if the file was opened successfully.  Otherwise,
# bail out.
if (fh)
{
  # At least in version 3, each component of the version number is separated
  # by a ', ' instead of a '.'
  ver = GetProductVersion(handle:fh);
  ver = str_replace(string:ver, find:', ', replace:'.');
  CloseFile(handle:fh);
  NetUseDel();
}
else
{
  NetUseDel();
  exit(1, "Unable to access Cerberus FTP file: " + exe);
}

if (ver)
{
  set_kb_item(name:"CerberusFTP/Version", value:ver);
  set_kb_item(name:"SMB/CerberusFTP/" + ver, value:path);

  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "Install Path : ", path, "\n",
      "Version      : ", ver, "\n"
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else exit(1, "Error retrieving version number from file: " + exe);

