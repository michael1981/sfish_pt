#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25161);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2007-2239");
  script_bugtraq_id(23816);
  script_xref(name:"OSVDB", value:"35602");

  script_name(english:"AXIS Camera Control (aka CamImage) AxisCamControl.ocx ActiveX SaveBMP Method Overflow");
  script_summary(english:"Checks version of CamImage control"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by a
buffer vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the 'CamImage' ActiveX control
included with AXIS Camera Control. 

The version of this ActiveX control on the remote host has a buffer
overflow involving its 'SaveBMP' method.  If an attacker can trick a
user on the affected host into visiting a specially-crafted web page,
he may be able to leverage this issue to execute arbitrary code on the
host subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.kb.cert.org/vuls/id/355809" );
 script_set_attribute(attribute:"see_also", value:"http://www.axis.com/techsup/software/acc/files/acc_security_update_1_00.pdf" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to AXIS Camera Control version 2.40.0.0 or later." );
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
file = NULL;

clsid = "{917623D1-D8E5-11D2-BE8B-00104B06BDE3}";
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


# Make sure the control exists.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:file);
ocx =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:file);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:ocx,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);

  # Check the version number.
  fix = split("2.40.0.0", sep:'.', keep:FALSE);
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
      security_hole(port:port, extra:report);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}


# Clean up.
NetUseDel();
