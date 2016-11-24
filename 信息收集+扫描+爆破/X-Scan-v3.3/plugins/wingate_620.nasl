#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(23732);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2006-4518");
  script_bugtraq_id(21295);
  script_xref(name:"OSVDB", value:"30691");

  script_name(english:"WinGate DNS Compressed Name Pointer DoS");
  script_summary(english:"Checks version number in WinGate's banner");

 script_set_attribute(attribute:"synopsis", value:
"The remote proxy is affected by a denial of service vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running WinGate, a Windows application
for managing and securing Internet access. 

The version of WinGate installed on the remote host contains a flaw
involving the processing of DNS requests with compressed name
pointers.  By sending a specially-crafted DNS request to a UDP port on
which WinGate is listening, an unauthenticated remote attacker can
cause the affected application to consume 100% of the available CPU,
thereby denying service to legitimate users." );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=444" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2006-11/0398.html" );
 script_set_attribute(attribute:"see_also", value:"http://forums.qbik.com/viewtopic.php?t=4215" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WinGate 6.2.0 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );


script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

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
key = "SOFTWARE\Qbik Software\Key Management\Products\Wingate";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Key Folder");
  if (!isnull(value)) path = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path)) {
  NetUseDel();
  exit(0);
}


# Check the version of the main exe.
info = "";
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\WinGate.exe", string:path);
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

# Check the version number.
if (!isnull(ver))
{
  fix = split("6.2.0.0", sep:'.', keep:FALSE);
  for (i=0; i<4; i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
      if (report_verbosity)
      {
        report = string(
          "Version ", version, " of WinGate is installed under :\n",
          "\n",
          "  ", path
        );
      }
      else report = NULL;

      security_warning(port:port, extra:report);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}


# Clean up.
NetUseDel();
