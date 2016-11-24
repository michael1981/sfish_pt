#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24913);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-1680");
  script_bugtraq_id(23291);
  script_xref(name:"OSVDB", value:"34319");

  script_name(english:"Yahoo! Messenger AudioConf ActiveX Control (yacscom.dll) Multiple Property Overflow");
  script_summary(english:"Checks version of AudioConf ActiveX control"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by a
buffer vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the 'AudioConf' ActiveX control
included with Yahoo! Messenger. 

The version of this ActiveX control on the remote host has a buffer
overflow triggered by calling the control's 'createAndJoinConference'
method with large values for the 'socksHostname' and 'hostname'
properties.  If an attacker can trick a user on the affected host into
visiting a specially-crafted web page, he may be able to leverage this
issue to execute arbitrary code on the host subject to the user's
privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-07-012.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/464607/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://messenger.yahoo.com/security_update.php?id=031207" );
 script_set_attribute(attribute:"solution", value:
"Update to the latest version of Yahoo! Messenger and ensure that the
version of the control is at least 1.0.0.48 or higher." );
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
file = NULL;

clsid = '{2B323CD9-50E3-11D3-9466-00A0C9700498}';
key = "SOFTWARE\Classes\CLSID\" + clsid +  "\InprocServer32";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value)) file = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(file))
{
  NetUseDel();
  exit(0);
}


# Determine the version from the control itself.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:file);
dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:file);
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
ver = NULL;
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}


# Check the version number.
if (!isnull(ver))
{
  fix = split("1.0.0.48", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
      report = string(
        "Version ", version, " of the control is installed as \n",
        "\n",
        "  ", file, "\n"
      );
      security_hole(port:port, extra: report);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}


# Clean up.
NetUseDel();
