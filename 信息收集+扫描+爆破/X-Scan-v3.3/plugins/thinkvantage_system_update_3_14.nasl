#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(32443);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2008-3249");
  script_bugtraq_id(29366);
  script_xref(name:"OSVDB", value:"45621");
  script_xref(name:"Secunia", value:"30379");

  script_name(english:"ThinkVantage System Update < 3.14 SSL Certificate Issuer Spoofing");
  script_summary(english:"Checks version in registry"); 

 script_set_attribute(attribute:"synopsis", value:
"A remote Windows host contains a program that is prone to a spoofing
attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running ThinkVantage System Update, a software
distribution tool for Lenovo computers. 

The version of System Update installed on the remote host reportedly
does not perform certificate chain verification when initiating an SSL
connection with an update server.  An attacker who could redirect
connections to a malicious server could leverage this issue to send
specially-crafted XML and EXE files in response to requests from
System Update, which would then lead to arbitrary code execution." );
 script_set_attribute(attribute:"see_also", value:"http://www.security-objectives.com/advisories/SECOBJADV-2008-01.txt" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-05/0320.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1bcf51b5" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to System Update 3.14 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");


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


# Determine where it's installed and its version / build.
build = NULL;
path = NULL;
version = NULL;

key = "SOFTWARE\Lenovo\System Update";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"InstallationDir");
  if (!isnull(value))
  {
    path = value[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  }

  value = RegQueryValue(handle:key_h, item:"Version");
  if (!isnull(value)) version = value[1];

  value = RegQueryValue(handle:key_h, item:"BuildDate");
  if (!isnull(value)) build = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path) || isnull(version))
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  exit(0);
}


# Make sure the affected file exists.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Client.dll", string:path);
NetUseDel(close:FALSE);

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
# Exit if it doesn't.
if (isnull(fh))
{
  NetUseDel();
  exit(0);
}
CloseFile(handle:fh);
NetUseDel();


# Check the version number.
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

fix = split("3.14", sep:'.', keep:FALSE);
for (i=0; i<max_index(fix); i++)
  fix[i] = int(fix[i]);

for (i=0; i<max_index(ver); i++)
  if ((ver[i] < fix[i]))
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "The following ThinkVantage System Update install is affected :\n",
        "\n",
        "  Version    : ", version, "\n",
        "  Build date : ", build, "\n",
        "  Path       : ", path, "\n"
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    break;
  }
  else if (ver[i] > fix[i])
    break;
