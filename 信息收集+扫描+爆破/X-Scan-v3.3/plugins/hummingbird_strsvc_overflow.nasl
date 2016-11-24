#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(42436);
  script_version("$Revision: 1.1 $");
  
  script_bugtraq_id(36868);
  script_xref(name:"OSVDB", value:"59749");
  script_xref(name:"Secunia", value:"37191");

  script_name(english:"Hummingbird STR Service Buffer Overflow");
  script_summary(english:"Checks version of STRsvc.exe");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
a buffer overflow vulnerability." );
  script_set_attribute(attribute:"description", value:
"Hummingbird STR service (STRsvc.exe) is installed on the remote host. 
It is included with EMC Documentum eRoom, OpenText Hummingbird, and
OpenText Search Server. 

The installed version is affected by a buffer overflow vulnerability. 
By sending a very large packet to the Hummingbird STR service, it may
be possible for an unauthenticated attacker to execute arbitrary code
with SYSTEM privileges.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-09-074" );
  script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2009-10/0197.html" );
  script_set_attribute(attribute:"solution", value:
"If using Documentum eRoom, upgrade to version 7.4.2 or later. 

If using OpenText Hummingbird or OpenText Search Server, contact the
vendor for a patch." );
  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/01"); # 7.4.2 Release Notes date.
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/10");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_services.nasl","smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

#
include("smb_func.inc");
include("smb_hotfixes.inc");

if (report_paranoia < 2)
{
  services = get_kb_item("SMB/svcs");
  if (services && "Hummingbird STR Service" >!< services)
    exit(0, "The Hummingbird STR Service is not running.");
}

if (!get_kb_item("SMB/Registry/Enumerated"))  exit(1,"The 'SMB/Registry/Enumerated' KB item is missing.");

# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();
if (!get_port_state(port)) exit(1, "Port "+port+" is not open.");
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

soc = open_sock_tcp(port);
if (!soc) exit(1,"Can't open socket on port "+port+".");

session_init(socket:soc, hostname:name);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) 
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to remote registry.");
}

# Find where it's installed.
path = NULL;

key = "SYSTEM\CurrentControlSet\Services\Hummingbird STR Service";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"ImagePath");
  if (!isnull(value)) path = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, "Hummingbird STR service is not installed..");
}

# Grab the file version of file STRsvc.exe.

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to "+share+" share.");
}

fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

ver  = NULL;

if (!isnull(fh))
{
 ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}

NetUseDel();

# Check the version number.
if (!isnull(ver))
{
  fixed_version = "6.0.1.823";
  fix = split(fixed_version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity > 0)
      {
	version = string(ver[0],".",ver[1],".",ver[2],".",ver[3]);
        report = string(
          "\n",
          "File              : ", path, "\n",
          "Installed version : ", version, "\n",
          "Fixed version     : ", fixed_version, "\n",
          "\n"
        );
        security_hole(port:port, extra:report);
      }
      else	 
      	security_hole(port);
        exit(0);
    }
    else if (ver[i] > fix[i])
      break;

 exit(0, "STRsvc.exe version "+version+" is installed and not vulnerable.");
}
else exit(1, "Can't get file version of 'STRsvc.exe'.");
