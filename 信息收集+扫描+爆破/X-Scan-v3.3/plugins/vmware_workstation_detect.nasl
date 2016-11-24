#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(26201);
  script_version("$Revision: 1.3 $");

  script_name(english:"VMware Workstation Detection");
  script_summary(english:"Detects if VMware Workstationis installed"); 
 script_set_attribute(attribute:"synopsis", value:
"An OS Virtualization application is installed on the remote host." );
 script_set_attribute(attribute:"description", value:
"VMware Workstation, an OS virtualization solution for Desktops and
Laptops that allows to run multiple operating systems on the same
host, is installed on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/products/ws/" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
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

name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if (!get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);

session_init(socket:soc, hostname:name);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(0);
}


hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}


path = NULL;

key = "SOFTWARE\VMware, Inc.\VMware Workstation";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  # If VMWare Workstation is installed...
  item = RegQueryValue(handle:key_h, item:"InstallPath");
  if (!isnull(item))
  {
    path = item[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);


if (!path)
{
 NetUseDel();
 exit(0);
}


share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\vmware.exe", string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
 NetUseDel();
 exit(0);
}

fh = CreateFile(file:exe, 
		desired_access:GENERIC_READ, 
		file_attributes:FILE_ATTRIBUTE_NORMAL, 
		share_mode:FILE_SHARE_READ, 
		create_disposition:OPEN_EXISTING);
if (!isnull(fh))
{
  ret = GetFileVersionEx(handle:fh);
  if (!isnull(ret)) children = ret['Children'];

  stringfileinfo = children['StringFileInfo'];
  if (!isnull(stringfileinfo))
  {
    foreach key (keys(stringfileinfo))
    {
      data = stringfileinfo[key];
      if (!isnull(data))
        ver  = data['ProductVersion'];
    }
  }
  CloseFile(handle:fh);
}

NetUseDel();

# nb: 
# 
# Resulting ver = x.x.x build-yyyyyy.
# But we avoid relying on 'build' because it may
# not work on non-english installs.
#

# Extract version info 

if (ver && ereg(pattern:"^[0-9]\.[0-9]\.[0-9] *.+-[0-9]+$",string:ver) )
  ver   =  ereg_replace(string:ver,pattern:"^([0-9]\.[0-9]\.[0-9]) *.+-[0-9]+$",replace:"\1");
else
 exit(0);

if (!isnull(ver))
{
 set_kb_item(name:"VMware/Workstation/Version", value:ver);

 report = string(
          "\n",
          "VMware Workstation version ", ver, " is installed under :\n",
          "\n",
          "  ", path, "\n"
    );
 security_note(port:port, extra:report);
}
