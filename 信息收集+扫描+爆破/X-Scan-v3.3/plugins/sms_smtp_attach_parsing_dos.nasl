#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25663);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-1792");
  script_bugtraq_id(24625);
  script_xref(name:"OSVDB", value:"36110");

  script_name(english:"Symantec Mail Security for SMTP libdayzero.dll Executable Parsing DoS");
  script_summary(english:"Checks version of SMS for SMTP");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by a
denial of service vulnerability." );
 script_set_attribute(attribute:"description", value:
"Symantec Mail Security for SMTP, which provides anti-spam and anti-
virus protection for the IIS SMTP Service, is installed on the remote
Windows host. 

The version of Symantec Mail Security for SMTP installed on the remote
host contains boundary errors in its detection of executable packers
in 'libdayzero.dll'.  Using a specially-crafted email message with an
executable attachment, a remote attacker may be able to leverage this
issue to crash the product's filter hub service (filter-hub.exe) and
cause the mail queue to backup." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2007-48/advisory/" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2007-06/0598.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/avcenter/security/Content/2007.06.26.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade as necessary to Symantec Mail Security for SMTP 5.0.1 and
apply patch 181 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Make sure the SMS for SMTP service is running, unless we're 
# being paranoid.
if (report_paranoia < 2)
{
  services = get_kb_item("SMB/svcs");
  if (
    !services ||
    ("SMSTomcat" >!< services && "Symantec Mail Security for SMTP" >!< services)
  ) exit(0);
}



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
key = "SOFTWARE\\Symantec\\SMSSMTP";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"LoadPoint");
  if (!isnull(value))
  {
    path = value[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}


# Grab the file version of the affected file.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\scanner\bin\libdayzero.dll", string:path);

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
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}


# Check the version number.
if (!isnull(ver))
{
  fix = split("5.0.1.181", sep:'.', keep:FALSE);
  for (i=0; i<4; i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      security_hole(port);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}


# Clean up.
NetUseDel();
