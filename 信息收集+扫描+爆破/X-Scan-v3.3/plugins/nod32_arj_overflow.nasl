#
# (C) Tenable Network Security
#



include("compat.inc");

if (description) {
  script_id(19700);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-2903");
  script_bugtraq_id(14773);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"19223");

  name["english"] = "NOD32 Antivirus ARJ Archive Handling Buffer Overflow Vulnerability";
  script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows application is prone to a buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running NOD32 Antivirus, from eset. 

The installed version of NOD32 Antivirus is reportedly prone to a
heap-based buffer overflow when processing ARJ archives with long
filenames.  An attacker may be able to exploit this issue to execute
arbitrary code on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2005-40/advisory/" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2005-09/0149.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade nod32.002 to version 1.034 build 1132 or later using the
online update process." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  summary["english"] = "Checks for ARJ archive handling buffer overflow vulnerability in NOD32 Antivirus";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("nod32_installed.nasl", "smb_hotfixes.nasl");
  script_require_keys("Antivirus/NOD32/installed", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");


if (!get_kb_item("Antivirus/NOD32/installed")) exit(1);
if (!get_kb_item("SMB/Registry/Enumerated")) exit(1);

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
if (rc != 1) exit(1);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm)) {
  NetUseDel();
  exit(1);
}


# Get the software's installation directory from the registry.
key = "SOFTWARE\Eset\Nod\CurrentVersion\Info";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  value = RegQueryValue(handle:key_h, item:"InstallDir");
  if (!isnull(value)) dir = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);


# If it's installed...
if (dir) {
  # Read version / build info directly from the archive support module.
  #
  # nb: the registry does hold the module's build number in 
  #     HKML\SOFTWARE\Eset\Nod\CurrentVersion\InstalledComponents\ArchivesBuild,
  #     but not its version number.
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:dir);
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1) {
    NetUseDel();
    exit(1);
  }

  file = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\nod32.002", string:dir);
  fh = CreateFile(
    file:file,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    data = ReadFile(handle:fh, length:256, offset:0);
    CloseFile(handle:fh);
    if (data) {
      ver = strstr(data, "version: ");
      if (ver) {
        ver = ver - "version: ";
        ver = ver - strstr(ver, '\n');
        ver = chomp(ver);
      }

      build = strstr(data, "build: ");
      if (build) {
        build = build - "build: ";
        build = build - strstr(build, '\n');
        build = chomp(build);
      }
    }

    # There's a problem if it's earlier than version 1.034 build 1132.
    if (
      ver && build &&
      (
        ver =~ "^(0\.|1\.0([0-2]|3[0-3]))" ||
        ver == "1.034" && int(build) < 1132
      )
    ) {
      security_hole(port);
    }
  }
}


# Clean up.
NetUseDel();
