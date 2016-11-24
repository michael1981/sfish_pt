#
#  (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(23637);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2006-5882");
  script_bugtraq_id(21007);
  script_xref(name:"OSVDB", value:"30294");

  script_name(english:"Broadcom Wireless Driver (BCMWL5.SYS) Probe Response SSID Overflow");
  script_summary(english:"Checks version of Broadcom wireless driver"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a wireless device driver that is prone to
a buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"The Windows remote host contains a Broadcom wireless device driver. 

The installed version of this driver on the remote host includes the
file 'bcmwl5.sys' that is reportedly affected by a stack-based
overflow vulnerability.  An attacker within wireless range of the
affected host may be able to leverage this issue using a 802.11 probe
response with a long SSID field to execute arbitrary kernel-mode code
on the affected host." );
 script_set_attribute(attribute:"see_also", value:"http://projects.info-pull.com/mokb/MOKB-11-11-2006.html" );
 script_set_attribute(attribute:"see_also", value:"http://isotf.org/advisories/zert-01-111106.htm" );
 script_set_attribute(attribute:"see_also", value:"http://isc.incidents.org/diary.php?storyid=1845" );
 script_set_attribute(attribute:"solution", value:
"Contact the device's manufacturer for an update." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);
name = kb_smb_name();
port = kb_smb_transport();
if (!get_port_state(port)) exit(0);
login = kb_smb_login();
pass = kb_smb_password();
domain = kb_smb_domain();


# Connect to the remote registry.
soc = open_sock_tcp(port);
if (!soc) exit(0);
session_init(socket:soc, hostname:name);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) exit(0);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}


# Check whether it's installed.
paths = make_array();
# - Linksys
fixes["Linksys"] = "4.100.15.5";
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{02AC211F-0026-4D6D-A5D8-429F94C86181}";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"InstallLocation");
  if (!isnull(value))
  {
    path = value[1] + "\Driver";
    paths[path] = "Linksys";
  }

  RegCloseKey(handle:key_h);
}
# - Zonet
# nb: I don't really know what the fix is, but "3.50.21.10" is known vulnerable.
if (report_paranoia < 2) fixes["Zonet"] = "3.50.21.11";
else fixes["Zonet"] = "9999";
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{BD3F013F-D0FE-4A4D-AB4A-56B856B9C2C4}";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
path = NULL;
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"LogFile");
  if (!isnull(value))
  {
    path = ereg_replace(pattern:"^(.*)\setup.ilg", replace:"\1", string:value[1]);
    paths[path] = "Zonet";
  }

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);


# If it is, get the version of the affected file.
foreach path (keys(paths))
{
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(0);
  }

  dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\bcmwl5.sys", string:path);
  fh = CreateFile(
    file               : dll,
    desired_access     : GENERIC_READ,
    file_attributes    : FILE_ATTRIBUTE_NORMAL,
    share_mode         : FILE_SHARE_READ,
    create_disposition : OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    ver = GetFileVersion(handle:fh);
    CloseFile(handle:fh);
  }

  # Check the version installed.
  vendor = paths[path];
  if (!isnull(ver) && !isnull(fixes[vendor]))
  {
    fix = split(fixes[vendor], sep:'.', keep:FALSE);
    for (i=0; i<4; i++)
      fix[i] = int(fix[i]);

    for (i=0; i<max_index(ver); i++)
    {
      if ((ver[i] < fix[i]))
      {
        version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
        report = string(
          "Version ", version, " of the Broadcom driver from ", vendor, " is installed\n",
          "under : \n",
          "\n",
          "  ", path, "\n",
          "\n"
        );
        security_hole(port:port, extra:report);

        NetUseDel();
        exit(0);
      }
      else if (ver[i] > fix[i])
        break;
    }
  }
}


# Clean up.
NetUseDel();
