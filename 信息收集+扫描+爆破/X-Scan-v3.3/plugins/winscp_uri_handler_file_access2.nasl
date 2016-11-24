#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(26027);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2007-4909");
  script_bugtraq_id(25655);
  script_xref(name:"OSVDB", value:"40519");

  script_name(english:"WinSCP URL Protocol Handler Arbitrary File Transfer");
  script_summary(english:"Checks version of WinSCP exe");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a program that allows arbitrary file
access." );
 script_set_attribute(attribute:"description", value:
"According to its version, the installation of WinSCP on the remote
host fails to completely sanitize input to the scp and sftp protocol
handlers.  If an attacker can trick a user on the affected host into
clicking on a malicious link, he may be able to initiate a file
transfer to or from the affected host." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/479298/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://winscp.net/eng/docs/history#4.0.4" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WinSCP version 4.0.4 or later." );
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
exe = NULL;

foreach handler (make_list("SCP", "SFTP"))
{
  key = "SOFTWARE\Classes\" + handler + "\shell\open\command";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(item))
    {
      exe = item[1];
      exe = ereg_replace(pattern:'^"([^"]+)".*$', replace:"\1", string:exe);
    }

    RegCloseKey(handle:key_h);
  }
  if (!isnull(exe)) break;
}
RegCloseKey(handle:hklm);
if (isnull(exe))
{
  NetUseDel();
  exit(0);
}


# Check the version of the main exe.
ver = NULL;

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
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}
NetUseDel();


# Check the version number.
if (!isnull(ver))
{
  fix = split("4.0.4.346", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      path = ereg_replace(pattern:"^(.+)\\[^\\]+$", replace:"\1", string:exe);
      version = string(ver[0], ".", ver[1], ".", ver[2]);

      report = string(
        "Version ", version, " of WinSCP is installed under :\n",
        "\n",
        "  ", path
      );
      security_hole(port:port, extra: report);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}
