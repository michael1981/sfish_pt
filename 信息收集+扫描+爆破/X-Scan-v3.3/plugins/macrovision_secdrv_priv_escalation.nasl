#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(28185);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-5587");
  script_bugtraq_id(26121);
  script_xref(name:"OSVDB", value:"41429");

  script_name(english:"Macrovision SafeDisc secdrv.sys Crafted METHOD_NEITHER IOCTL Local Overflow");
  script_summary(english:"Checks version of SECDRV.SYS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a kernel driver that is prone to a
local privilege escalation vulnerability." );
 script_set_attribute(attribute:"description", value:
"Macrovision SafeDisc, a copy-protection application for Microsoft
Windows, is installed on the remote host. 

The 'SECDRV.SYS' driver included with the version of SafeDisc
currently installed on the remote host enables a local user to gain
SYSTEM privileges using a specially-crafted argument to the
METHOD_NEITHER IOCTL." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/482482/100/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/technet/security/advisory/944653.mspx" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Macrovision SECDRV.SYS Driver version 4.3.86 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl", "os_fingerprint.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");


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
if (rc != 1) {
  NetUseDel();
  exit(0);
}


# Grab the file version of the affected file.
winroot = hotfix_get_systemroot();
if (!winroot) exit(1);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:winroot);
sys =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\System32\drivers\secdrv.sys", string:winroot);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:sys,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
ver = NULL;
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  # nb: the unpatched driver has no version number on Windows XP.
  if (isnull(ver))
  {
    os = get_kb_item("Host/OS");
    if (os && "XP" >< os) ver = make_list(0, 0, 0, 0);
  }
  CloseFile(handle:fh);
}




# Check the version number.
if (!isnull(ver))
{
  fix = split("4.3.86.0", sep:'.', keep:FALSE);
  for (i=0; i<4; i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
      report = string(
        "Version ", version, " of the driver is installed as :\n",
        "\n",
        "  ", winroot, "\\System32\\drivers\\secdrv.sys\n"
      );
      security_warning(port:port, extra:report);
      set_kb_item(name:"Host/SMB/secdrv/CVE-2007-5587", value:TRUE);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}


# Clean up.
NetUseDel();
