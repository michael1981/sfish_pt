#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(31857);
  script_version("$Revision: 1.3 $");

  script_name(english:"Symantec Scan Engine Detection");
  script_summary(english:"Checks version of Symantec Scan Engine"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an antivirus engine installed." );
 script_set_attribute(attribute:"description", value:
"Symantec Scan Engine, a programming interface to integrate various
antivirus technologies, is installed on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9627b3b9" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

#

include("global_settings.inc");
include("smb_func.inc");

# Figure out where the installer recorded information about it.

list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (isnull(list)) exit(0);

installstring = NULL;
product_name  = NULL;

foreach name (keys(list))
{
  prod = list[name];
  if (prod && "Symantec AntiVirus Scan Engine" >< prod || "Symantec Scan Engine" >< prod)
  {
   installstring = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(SOFTWARE\/Microsoft\/Windows\/CurrentVersion\/Uninstall\/.+)\/DisplayName$", replace:"\1", string:name);
   installstring = str_replace(find:"/", replace:"\", string:installstring);
   product_name = prod;
   break;
  }
}

if(isnull(installstring) || isnull(product_name)) exit(0);

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
key = installstring;

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  # If Scan Engine is installed...
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
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\symcscan.exe", string:path);
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

ver = NULL;

if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}
NetUseDel();


if(!isnull(ver))
{
 se_version = string(ver[0],".",ver[1],".",ver[2],".",ver[3]);
 set_kb_item(name:string("Symantec/",product_name,"/Version"), value:se_version);
 # This will either set - Symantec/Symantec AntiVirus Scan Engine/Version
 #	 or 		  Symantec/Symantec Scan Engine/Version
 
 if(report_verbosity)
 {
  report = string(
          "\n",
          product_name, " version ", se_version,"\n", 
	  " is installed under :\n",
	 "\n",
          "  ", path, "\n"
    );
   security_note(port:port, extra:report);
 }
 else
  security_note(port:port);
}
exit(0);







