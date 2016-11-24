#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(38651);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(34764);
 
  script_name(english:"ESET Anti-Virus .CAB File Scan Evasion");
  script_summary(english:"Checks signature database version");
  script_set_attribute(attribute:"synopsis", value:
"The remote host has an anti-virus software that is affected by
a scan evasion vulnerability." );
  script_set_attribute(attribute:"description", value:
"The remote host has an anti-virus product from ESET installed. The 
virus signature database version of the installed anti-virus product is 
older than 4036, and hence it may be possible for certain .CAB files 
to evade detection from the scanning engine." );
  script_set_attribute(attribute:"see_also", value:"http://blog.zoller.lu/2009/04/nod32-eset-cab-generic-evasion-limited.html" );
  script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2009-04/0291.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.eset.com/support/updates.php (Search for 4036)" );
  script_set_attribute(attribute:"solution", value:"Update to virus signature database version 4036 or later.");
  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );
 
  script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);

name    = kb_smb_name();
login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();

port    = kb_smb_transport();
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

# Check if the software is installed.
path = NULL;
sigs_target_update = NULL;
pname = NULL; # Product Name

key = "SOFTWARE\Eset\Nod\CurrentVersion\Info";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h)) 
{
  value = RegQueryValue(handle:key_h, item:"InstallDir");
  if (!isnull(value)) 
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:value[1]);

  value = RegQueryValue(handle:key_h, item:"ProductName");
  if (!isnull(value))
    pname = value[1];

  # Sig version is stored in the registry.
  value = RegQueryValue(handle:key_h, item:"CurrentVersion");
  if (!isnull(value)) 
    sigs_target_update = ereg_replace(pattern:"^([0-9]+).*", string:value[1], replace:"\1");

  RegCloseKey (handle:key_h);
}

# nb: 
# In new versions 3.667 and older, information is stored
# in different registry locations.

if ("Obsolete" >< path || isnull(path)) 
{
  key = "SOFTWARE\ESET\ESET Security\CurrentVersion\Info";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

   if (!isnull(key_h))
   {
     value = RegQueryValue(handle:key_h, item:"InstallDir");
     if (!isnull(value))
      path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:value[1]);

     value = RegQueryValue(handle:key_h, item:"ProductName");
      if (!isnull(value))
        pname = value[1];

     # Sig version is stored in the registry.
     value = RegQueryValue(handle:key_h, item:"ScannerVersion");
     if (!isnull(value))
      sigs_target_update = ereg_replace(pattern:"^([0-9]+).*", string:value[1], replace:"\1");

     RegCloseKey (handle:key_h);
   }
}

RegCloseKey(handle:hklm);


# If it is installed, do a sanity check to check if
# egui.exe/nod32.exe exists.

if (!isnull(path))
{
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);

  if ("SOFTWARE\ESET\ESET Security\CurrentVersion\Info" >< key)
  exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\egui.exe", string:path);
  else
  exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\nod32.exe", string:path);

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

  if (!isnull(fh))
    {
      version = GetFileVersion(handle:fh);
      CloseFile(handle:fh);
    }
}
NetUseDel();

if (isnull(path) || isnull(sigs_target_update) || isnull(version)) exit(0);  

if(sigs_target_update < 4036)
{
  if(report_verbosity > 0 && !isnull(pname))
  {
   report = string(
     "\n",
     pname," is installed under :\n",
     "\n",
     "  ", path, "\n",
     "\n",
     "The virus signature database version ",sigs_target_update, " is out of date.",
     "\n"
     );
     security_warning(port:port, extra:report);
  }
  else
    security_warning(port);
}



