#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(24277);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2007-0796");
  script_bugtraq_id(22393);
  script_xref(name:"OSVDB", value:"33097");

  script_name(english:"WinProxy < 6.1r1c HTTP CONNECT Request Remote Overflow");
  script_summary(english:"Checks for WinProxy < 6.1r1c");

 script_set_attribute(attribute:"synopsis", value:
"The remote HTTP proxy is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running WinProxy, a proxy server for Windows. 

The version of WinProxy installed on the remote host reportedly
contains a design issue that may result in a buffer overflow
vulnerability.  Using a specially-crafted HTTP CONNECT request, a
remote attacker may be able to leverage this issue to execute
arbitrary code on the affected host subject to the privileges under
which the service runs." );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=471" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2007-02/0107.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WinProxy version 6.1r1c or later as it is rumored to
address the issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );


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


# Determine where it's installed.
exe = NULL;
key = "SOFTWARE\Blue Coat Systems\WinProxy";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey) && subkey =~ "^[0-9]")
    {
      key2 = key + "\" + subkey;
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        value = RegQueryValue(handle:key2_h, item:"Path");
        if (!isnull(value)) exe = value[1];

        RegCloseKey(handle:key2_h);
      }
    }
  }
  RegCloseKey (handle:key_h);
}
RegCloseKey(handle:hklm);


# If it is...
if (exe)
{
  # Determine its version from the executable itself.
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
  if (!isnull(fh))
  {
    ver = GetFileVersion(handle:fh);
    CloseFile(handle:fh);
  }

  # There's a problem if the version is < 6.1.25.0
  if (!isnull(ver))
  {
    fix = split("6.1.25.0", sep:'.', keep:FALSE);
    for (i=0; i<4; i++)
      fix[i] = int(fix[i]);

    for (i=0; i<max_index(ver); i++)
      if ((ver[i] < fix[i]))
      {
        version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
        report = string(
          "WinProxy version ", version, " is installed as :\n",
          "\n",
          "  ", exe
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
