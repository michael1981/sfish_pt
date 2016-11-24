#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(31856);
  script_version("$Revision: 1.4 $");

  script_name(english:"Symantec Mail Security for Microsoft Exchange Installed");
  script_summary(english:"Checks version of Symantec Mail Security for Microsoft Exchange"); 
 
  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host has an anti-virus software installed."
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "Symantec Mail Security for Microsoft Exchange, a commercial anti-virus\n",
      "software that offers mail protection against viruses, spam and other\n",
      "security threats is installed on the remote host."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e59fb045"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"n/a"
  );
  script_set_attribute(
    attribute:"risk_factor", 
    value:"None"
  );
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
  if (prod && "Symantec Mail Security for Microsoft Exchange" >< prod)
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
  # If SMSE is installed...
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
parent_dir =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
 NetUseDel();
 exit(0);
}

# Version info needs to be extracted from a different location for 6.x
files = make_list(
  "\UI\Symantec.MailSecurity.UI.exe",
  "\CMaF\2.0\bin\Products\SMSMSE\6.0\SAVFMSERemote.exe"
);

foreach file (files)
{
  exe = parent_dir + file;
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
  
  if(!isnull(ver))
  {
   smse_version = string(ver[0],".",ver[1],".",ver[2],".",ver[3]);
   set_kb_item(name:"Symantec/SMSE/Version", value:smse_version);
  
   if(report_verbosity)
   {
     report += string(
       "\n",
       "  Install Path : ", path, "\n",
       "  Version      : ", smse_version, "\n"
     );
     security_note(port:port, extra:report);
   }
   else
    security_note(port:port);
  
  NetUseDel();
  exit(0);
  }
}

NetUseDel();
exit(1, "SMSMSE wasn't detected");
