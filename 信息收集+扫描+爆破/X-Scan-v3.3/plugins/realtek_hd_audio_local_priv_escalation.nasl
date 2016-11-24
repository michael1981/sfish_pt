#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32195);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2008-1931", "CVE-2008-1932");	
  script_bugtraq_id(28909);
  script_xref(name:"OSVDB", value:"44642");
  script_xref(name:"OSVDB", value:"44643");
	
  script_name(english:"Realtek HD Audio Codec Drivers Multiple Local Privilege Escalation Vulnerabilities");
  script_summary(english:"Checks version of Realtek HD Audio driver RTKVHDA.sys"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by multiple
local privilege escalation issues." );
 script_set_attribute(attribute:"description", value:
"The remote host has Realtek HD Audio drivers for Windows Vista 
installed.

The audio driver 'RTKVHDA.sys' is affected by multiple local privilege
escalation issues. An attacker with local interactive access to the 
system may be able to exploit this issue and execute arbitrary code
with SYSTEM level privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/491249" );
 script_set_attribute(attribute:"see_also", value:"http://www.wintercore.com/advisories/advisory_W010408.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?66ac9a21" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );
 script_set_attribute(attribute:"solution", value:"Update to version 6.0.1.5605 or later");
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

# Exit if remote host is not Vista  

if ( "6.0" >!< get_kb_item("SMB/WindowsVersion")) exit(0);

# Figure out where the installer recorded information about it.

list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (isnull(list)) exit(0);

installstring = NULL;
foreach name (keys(list))
{
  prod = list[name];
  if (prod && "Realtek High Definition Audio Driver" >< prod)
  {
   installstring = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(SOFTWARE\/Microsoft\/Windows\/CurrentVersion\/Uninstall\/.+)\/DisplayName$", replace:"\1", string:name);
   installstring = str_replace(find:"/", replace:"\", string:installstring);
   break;
  }
}

if(isnull(installstring)) exit(0);

# Get the install path

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

key = installstring;
path = NULL;

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  # If Realtek audio driver is installed...
  item = RegQueryValue(handle:key_h, item:"InstallLocation");
  if (!isnull(item))
  {
    path = item[1];
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
sys =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\RTKVHDA.sys", string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
 NetUseDel();
 exit(0);
}

fh = CreateFile(file:sys, 
	desired_access:GENERIC_READ, 
	file_attributes:FILE_ATTRIBUTE_NORMAL, 
	share_mode:FILE_SHARE_READ, 
	create_disposition:OPEN_EXISTING);

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
  # Version of the driver that is not vulnerable
  fix = split("6.0.1.5605", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity)
      {
	version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
        report = string(
          "\n",
          "Version ", version, " of the affected audio driver is installed as :\n", 
          "\n",
          "  ", path, "\\RTKVHDA.sys\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      break;
    }
    else if (ver[i] > fix[i])
      break;
} 
