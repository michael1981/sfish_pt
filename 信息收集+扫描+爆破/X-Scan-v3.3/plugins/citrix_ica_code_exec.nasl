#
#  (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(24742);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2007-1196");
  script_bugtraq_id(22762);
  script_xref(name:"OSVDB", value:"33833");

  script_name(english:"Citrix Presentation Server Client Unspecified Remote Code Execution");
  script_summary(english:"Checks version of Citrix ICA client"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by a
remote code execution vulnerability." );
 script_set_attribute(attribute:"description", value:
"Citrix Presentation Server Client is installed on the remote host.  It
is used to access published resources such as applications stored on
servers running Citrix Presentation Server. 

The version of Citrix Presentation Server Client on the remote host is
reportedly affected by an unspecified remote code execution
vulnerability involving ICA connections through proxy servers.  An
attacker may be able to leverage this issue to execute arbitrary code
on the remote host subject to the user's privileges if he can trick
the user into visiting a malicious web site." );
 script_set_attribute(attribute:"see_also", value:"http://support.citrix.com/article/CTX112589" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Citrix Presentation Server Client for Windows version 10.0
or later." );
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
key = "SOFTWARE\Citrix\Install";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey) && subkey =~ "^{")
    {
      key2 = key + "\" + subkey;
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        value = RegQueryValue(handle:key2_h, item:"InstallLocation");
        if (!isnull(value))
        {
          path = value[1];
          path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
        }
        RegCloseKey(handle:key2_h);
      }
    }
  }
  RegCloseKey (handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}


# Determine the version from the ICA Client.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\wfica32.exe", string:path);
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

  # There's a problem if the version of the ICA Client is earlier than 10.
  if (!isnull(ver) && ver[0] < 10)
  {
    version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
    report = string(
      "Version ", version, " of the Citrix ICA Client is installed under :\n",
      "\n",
      "  ", path, "\n"
    );
    security_hole(port:port, extra:report);
  }
}


# Clean up.
NetUseDel();
