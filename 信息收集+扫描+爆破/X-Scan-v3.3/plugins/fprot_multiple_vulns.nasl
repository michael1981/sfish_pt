#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33549);
  script_version("$Revision: 1.4 $");

  script_bugtraq_id(30258, 30253);	
  script_cve_id("CVE-2008-3244", "CVE-2008-3243");
  script_xref(name:"OSVDB", value:"47297");
  script_xref(name:"OSVDB", value:"47298");
  script_xref(name:"OSVDB", value:"47299");
  script_xref(name:"OSVDB", value:"47300");
	
  script_name(english:"F-PROT Antivirus Engine < 4.4.4 Multiple File Handling DoS Vulnerabilities");
  script_summary(english:"Checks if vulnerable version of F-PROT Antivirus engine is installed"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The version of F-PROT anti-virus installed on the remote Windows
host contains flaws in the way it handles CHM, UPX-compressed, 
ASPack-compressed and certain Microsoft office files.

- A malformed CHM file containing '0xffffffff' in the 'nb_dir' 
  field could crash the application.

- A malformed UPX-compressed or ASPack-compressed  file could
  crash the application.

- A specially crafted Microsoft office document could trigger 
  a infinite loop, causing a denial of service condition." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2008/Jul/0275.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.f-prot.com/download/ReleaseNotesWindows.txt" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to F-PROT anti-virus engine 4.4.4 included with F-PROT
anti-virus version 6.0.9.0." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

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

# Figure out where the installer recorded information about it.

list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (isnull(list)) exit(0);

installstring = NULL;
foreach name (keys(list))
{
  prod = list[name];
  if (prod && ereg(pattern:"^F-PROT Antivirus for Windows", string:prod))
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
dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\FPAVENG.dll", string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
 NetUseDel();
 exit(0);
}

fh = CreateFile(file:dll, 
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
  # Version that is not vulnerable.
  fix = split("4.4.4", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity)
      { 
        version = string(ver[0], ".", ver[1], ".", ver[2]);
        report = string(
          "\n",
          "Version ", version, " of F-PROT engine is installed on the\n",
          "remote host.\n"
        );
        security_warning(port:port, extra:report);
      }
      else security_warning(port);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}       



