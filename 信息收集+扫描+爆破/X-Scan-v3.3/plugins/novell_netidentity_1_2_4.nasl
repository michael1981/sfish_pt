#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(36103);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-1350");
  script_bugtraq_id(34400);
  script_xref(name:"OSVDB", value:"53351");
  script_xref(name:"Secunia", value:"34574");

  script_name(english:"Novell NetIdentity Agent < 1.2.4 Arbitrary Pointer De-reference Code Execution");
  script_summary(english:"Checks version of xtagent.exe");
 
  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Windows host allows remote execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The 'xtagent.exe' program included with the version of Novell's\n",
      "NetIdentity Agent installed on the remote Windows host contains an\n",
      "arbitrary pointer de-reference vulnerability.  Using specially crafted\n",
      "RPC messages over the 'XTIERRPCPIPE' named pipe, an attacker who can\n",
      "establish a valid IPC$ connection can leverage this issue to execute\n",
      "arbitrary code with system privileges on the affected host."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.zerodayinitiative.com/advisories/ZDI-09-016/"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://archives.neohapsis.com/archives/fulldisclosure/2009-04/0053.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://download.novell.com/Download?buildid=6ERQGPjRZ8o~"
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Upgrade to NetIdentity Agent 1.2.4, build 1.2.612 or later."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C"
  );
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Make sure the affected service is running, unless we're being paranoid.
if (report_paranoia < 2)
{
  services = get_kb_item("SMB/svcs");
  if (
    services && 
    "XTAgent" >!< services &&
    "Novell XTier Agent Services" >!< services
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


# Find the agent's location.
file = NULL;

key = "SOFTWARE\Novell\NetIdentity\SharedDLLs";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[0]; ++i)
  {
    value = RegEnumValue(handle:key_h, index:i);
    if (strlen(value[1]) && value[1] =~ "xtagent\.exe$")
    {
      file = value[1];
      break;
    }
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(file))
{
  NetUseDel();
  exit(0);
}


# Grab the version from the executable.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:file);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:file);
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
  fix = split("1.2.4.5", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity > 0)
      {
        version = string(ver[0], ".", ver[1], ".", ver[2], " Build ", ver[3]);

        report = string(
          "\n",
          "  File    : ", file, "\n",
          "  Version : ", version, "\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}
