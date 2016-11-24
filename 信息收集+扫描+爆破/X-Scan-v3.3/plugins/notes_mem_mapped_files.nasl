#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(27574);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2007-5544");
  script_bugtraq_id(26146);
  script_xref(name:"OSVDB", value:"40948");

  script_name(english:"IBM Lotus Notes / Domino Client Memory Mapped Files Privilege Escalation");
  script_summary(english:"Checks version of Lotus Notes and notes.ini settings"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by an
unauthorized access vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of Lotus Notes installed on the remote Windows host fails
to adequately protect certain memory mapped files used by the
application for inter-process communications.  In a shared user
environment, a local user may be able to leverage this issue to read
from these files, leading to information disclosure, or write to them,
possibly injecting active content such as Lotus Script." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/482694/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg21257030" );
 script_set_attribute(attribute:"solution", value:
"Upgrade as necessary to Lotus Notes Client version 6.5.6 / 7.0.3 / 8.0
or later and then edit the 'notes.ini' configuration file as described
in the vendor advisory above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/name", "SMB/login", "SMB/password");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");


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
if (rc != 1) exit(0);


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}


# Determine where it's installed.
path = NULL;

key = "SOFTWARE\Lotus\Notes";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  value = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(value))
  {
    path = value[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);  
}


# Determine the version of the Notes client.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\notes.exe", string:path);
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
if (isnull(fh))
{
  NetUseDel();
  exit(0);
}
ver = GetFileVersion(handle:fh);
CloseFile(handle:fh);
if (isnull(ver))
{
  NetUseDel();
  exit(0);
}


# If it's an affected version...
#
# nb: ver[2] is multiplied by 10.
if (
  (int(ver[0]) == 6 && int(ver[1]) == 5 && int(ver[2]) < 6) ||
  (int(ver[0]) == 7 && int(ver[1]) == 0 && int(ver[2]) < 30)
)
{
  security_warning(port);
}
# Otherwise, make sure the setting is present in notes.ini.
else 
{
  ini =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\notes.ini", string:path);
  fh = CreateFile(
    file:ini,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (isnull(fh))
  {
    NetUseDel();
    exit(0);
  }
  # no more than 10K.
  chunk = 10240;
  size = GetFileSize(handle:fh);
  if (size > 0) 
  {
    if (chunk > size) chunk = size;
    data = ReadFile(handle:fh, length:chunk, offset:0);
  }
  CloseFile(handle:fh);

  if (data)
  {
    # There's a problem if the setting doesn't exist.
    if (!egrep(pattern:"^SharedMemoryAllowOnly=1", string:data))
    {
      security_warning(port);
    }
  }
}


# Clean up.
NetUseDel();
