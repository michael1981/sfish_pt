#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(28330);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2007-6181");
  script_bugtraq_id(26557);
  script_xref(name:"OSVDB", value:"43714");

  script_name(english:"Cygwin < 1.5.24 cygwin1.dll Crafted Filename Handling Overflow");
  script_summary(english:"Checks version of cygwin1.dll");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is prone to a
buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"Cygwin, a Linux-like environment for Windows, is installed on the
remote host. 

The version of Cygwin installed on the remote host is affected by a
heap-based buffer overflow vulnerability involving a filename length
check.  Using a filename between 233 and 239 characters, an attacker
who can create a file on the remote can leverage this issue to execute
arbitrary code on the affected host subject to the privileges under
which Cygwin operates." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/484153/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://cygwin.com/ml/cygwin-developers/2007-11/msg00001.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Cygwin 1.5.24 as that version is reportedly not affected." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C" );
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


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}


# Make sure it's installed.
path = NULL;

key = "SOFTWARE\Cygnus Solutions\Cygwin\mounts v2\/usr/bin";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"native");
  if (!isnull(value))
  {
    path = value[1];
    path = str_replace(find:'/', replace:'\\', string:path);
  }

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}


# Grab the file version of the affected file.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
dll = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\cygwin1.dll", string:path);
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
NetUseDel();


# Check the version number.
if (!isnull(ver))
{
  # nb: 1005.24.0.0 is the file version from version 1.5.24.
  fix = split("1005.24.0.0", sep:'.', keep:FALSE);
  for (i=0; i<4; i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      security_hole(port);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}
