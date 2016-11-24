#
#  (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(20975);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2005-3525");
  script_bugtraq_id(16791);
  script_xref(name:"OSVDB", value:"23461");

  script_name(english:"ShockWave Player ActiveX Installer Buffer Overflow");
  script_summary(english:"Checks version of ShockWave installer ActiveX control"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by a
buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host contains an ActiveX control associated with
Macromedia's ShockWave Player installer that has an exploitable
stack-based buffer overflow.  It may be possible for an attacker to
execute arbitrary code on the remote host subject to the user's
privileges by tricking a user into visiting a malicious web site." );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-06-002.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.macromedia.com/devnet/security/security_zone/apsb06-02.html" );
 script_set_attribute(attribute:"solution", value:
"The vendor claims the issue occurs only in the installer so there is
no need for action." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
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
if (rc != 1) {
  NetUseDel();
  exit(0);
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm)) {
  NetUseDel();
  exit(0);
}


# Determine if the control is installed.
clid = "166B1BCA-3F9C-11CF-8075-444553540000";
key = "SOFTWARE\Classes\CLSID\{" + clid +  "}";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value)) name = value[1];
  else name = NULL;
 
  RegCloseKey(handle:key_h);
}
else name = NULL;


# If it is, get its location.
if (name && "Shockwave" >< name) {
  # Determine where it's installed.
  key = "SOFTWARE\Classes\CLSID\{" + clid + "}\InprocServer32";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h)) {
    value = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(value)) file = value[1];
    else file = NULL;

    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);


# If the location's available...
if (file ) {
  # Determine the version from the DLL itself.
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:file);
  dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:file);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1) {
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
  if (!isnull(fh)) {
    ver = GetFileVersion(handle:fh);
    CloseFile(handle:fh);
  }

  # There's a problem if the version number is < 10.1.0.11.
  if (
    !isnull(ver) &&
    (
      int(ver[0]) < 10 ||
      (
        int(ver[0]) == 10 &&
        (
          int(ver[1]) < 1 ||
          int(ver[1]) == 1 && int(ver[2]) == 0 && int(ver[3]) < 11
        )
      )
    )
  ) {
    if (report_verbosity > 1) {
      version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
      report = string(
        "Version ", version, " of the control is installed as \n",
        "\n",
        "  ", file, "\n"
      );
    }
    else report = NULL;

    security_hole(port:port, extra:report);
  }
}


# Clean up.
NetUseDel();
