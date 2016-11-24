#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(38663);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2009-2454");
  script_bugtraq_id(34761);
  script_xref(name:"OSVDB", value:"54133");
  script_xref(name:"Secunia", value:"34868");

  script_name(english:"Citrix Web Interface 4.6 / 5.0 / 5.0.1 Unspecified XSS");
  script_summary(english:"Checks the Version of Citrix Web Interface");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web application that is affected by a
cross-site scripting vulnerability." );
  script_set_attribute(attribute:"description", value:
"The remote host contains a version of Citrix Web Interface earlier
than 5.1.0.  Such versions are reportedly affected by an as-yet
unspecified cross-site scripting vulnerability.  An attacker could
exploit this issue to steal cookie based authentication and launch
other attacks." );
  script_set_attribute(attribute:"see_also", value:"http://support.citrix.com/article/CTX120697" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Citrix Web Interface 5.1.0 or later." );
  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

#

include("global_settings.inc");
include("smb_func.inc");

# Connect to the appropriate share
if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);
name    = kb_smb_name();
port    = kb_smb_transport();
login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();

soc = open_sock_tcp(port);
if (!soc) exit(0);

session_init(socket:soc, hostname:name);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

# Connect to the remote registry
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}
 
path = NULL;

# Determine the install location
key = "SOFTWARE\Citrix\Web Interface";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey) && subkey =~ "^[0-9.]+$")
    {
      key2 = key + "\" + subkey;
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        value = RegQueryValue(handle:key2_h, item:"Common Files Location");
        if (!isnull(value)) path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:value[1]);
        RegCloseKey(handle:key2_h);
      }
    }
  }
  RegCloseKey(handle:key_h);
}

if (isnull(path))
{
  NetUseDel();
  exit(0);
}

# Determine the version info from sitemgr.exe
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\sitemgr.exe", string:path);
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
  version = string(ver[0], ".", ver[1], ".", ver[2]);
  for(i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  if (
    (ver[0] == 4 && ver[1] == 6) ||
    (ver[0] == 5 && ver[1] == 0 && ver[2] <= 1)
  )
  {
    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "Citrix Web Interface ", version, " is installed on the remote host.\n"
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port:port);
  }
}
