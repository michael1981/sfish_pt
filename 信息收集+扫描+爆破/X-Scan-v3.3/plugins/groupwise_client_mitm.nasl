#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25769);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2007-2513");
  script_bugtraq_id(24258);
  script_xref(name:"OSVDB", value:"35942");

  script_name(english:"Novell GroupWise Authentication Credentials MiTM Disclosure");
  script_summary(english:"Checks version of grpwise.exe");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of the Novell GroupWise Client installed on the remote
host reportedly allows a remote attacker to intercept authentication
credentials via a man-in-the-middle attack." );
 script_set_attribute(attribute:"see_also", value:"http://www.cirosec.de/deutsch/dienstleistungen/advisory_040607.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3d714983" );
 script_set_attribute(attribute:"solution", value:
"Upgrade GroupWise clients to GroupWise 7 SP2 dated May 24, 2007 or
newer / 6.5 post-SP6 dated May 22, 2007 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N" );
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


# Make sure it's installed.
path = NULL;

key = "SOFTWARE\Clients\Mail\GroupWise\Shell\Open\Command";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value)) 
  {
    path = ereg_replace(pattern:'^"([^"]+)".*', replace:"\1", string:value[1]);
    path = ereg_replace(pattern:"^(.+)\\\[^\]+\.exe", replace:"\1", string:path);
  }

  RegCloseKey (handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}


# Grab the file version of the client.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\grpwise.exe", string:path);

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
  if (int(ver[0]) == 7) fixed = "7.0.2.562";
  else if (int(ver[0]) < 7) fixed = "6.57.0.0";
  else exit(0);

  fix = split(fixed, sep:'.', keep:FALSE);
  for (i=0; i<4; i++)
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
