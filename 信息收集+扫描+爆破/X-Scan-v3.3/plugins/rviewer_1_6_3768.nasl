#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(26062);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2007-4750", "CVE-2007-4751");
  script_bugtraq_id(25591);
  script_xref(name:"OSVDB", value:"40544");
  script_xref(name:"OSVDB", value:"40545");

  script_name(english:"R-Viewer < 1.6.3768 Multiple Vulnerabilities");
  script_summary(english:"Checks version of rview.exe");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a program that is affected by multiple
issues." );
 script_set_attribute(attribute:"description", value:
"R-Viewer, a secure document viewer from remotedocs.com, is installed
on the remote host. 

According to the registry, the installation of R-Viewer on the remote
Windows host allows arbitrary code to be executed without a user's
knowledge and stores unencrypted copies of previously-opened documents
in temporary directories.  If an attacker can trick a user into
opening a specially-crafted RDZ file, he can leverage these issues to
view files or execute code on the affected system subject to the
user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/content/en/us/enterprise/research/SYMSA-2007-009.txt" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/479718" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to R-Viewer version 1.6.3768 or later." );
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


# Check whether it's installed.
path = NULL;

key = "SOFTWARE\Classes\RemoteDocs.PackageFile\Shell\Open\Command";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value))
  {
    path = value[1];
    path = ereg_replace(pattern:'^"([^"]+)".*', replace:"\1", string:path);
    if (ereg(pattern:"rview\.exe ?", string:path, icase:TRUE))
      path = ereg_replace(pattern:"^(.+)\\\[^\]+\.exe( .+)?$", replace:"\1", string:path);
    else path = NULL;
  }

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}


# Check the version of the main exe.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\rview.exe", string:path);
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
  # nb: the fileversion for rview.exe from 1.6.3768 is 1.6.0.3763.
  fix = split("1.6.0.3763", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
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
