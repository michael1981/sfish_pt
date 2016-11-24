#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(42844);
  script_version("$Revision: 1.1 $");
  
  script_cve_id("CVE-2009-1628");
  script_bugtraq_id(35494);
  script_xref(name:"OSVDB", value:"55435");
  script_xref(name:"Secunia", value:"35572");

  script_name(english:"Unisys Business Information Server Stack Overflow");
  script_summary(english:"Checks version of mnet.exe");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by a
stack overflow vulnerability." );

  script_set_attribute(attribute:"description", value:
"Unisys Business Information Server is installed on the remote system. 

The installed version is affected by a stack overflow vulnerability. 
By sending a specially crafted request to the remote service, an
attacker may be able to overflow the stack, and potentially execute
arbitrary code with system level privileges." );

  script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=808" );
  script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2009-06/0263.html" );
  script_set_attribute(attribute:"see_also", value:"ftp://ftp.support.unisys.com/pub/mapper/NT/BIS10.1/Readme.txt" );

  script_set_attribute(attribute:"solution", value:
"Apply vendor supplied patches." );

  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/06/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/18");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies( "smb_hotfixes.nasl","unisys_bis_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445,3986,"Services/unisys-bis");

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");

if(report_paranoia < 2)
{
 if(!get_kb_item("Services/unisys-bis")) exit(1, "The 'Services/unisys-bis' KB item is missing.");
}

if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "The 'SMB/Registry/Enumerated' KB item is missing.");

# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();
if (!get_port_state(port))  exit(1, "Port "+port+" is not open.");
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

soc = open_sock_tcp(port);
if (!soc) exit(1,"Can't open socket on port "+port+".");

session_init(socket:soc, hostname:name);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) {
  NetUseDel();
  exit(1,"Can't connect to IPC$ share.");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
   exit(1,"Can't connect to remote registry.");
}


key = "SOFTWARE\Unisys Corporation\Business Information Server";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (isnull(key_h))
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  exit(0, "Unisys BIS is not installed.");
}

# Find where it's installed.
path = NULL;

key = "SOFTWARE\Unisys\MAPPER System";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"SharedComponentsPath");
  if (!isnull(value)) path = value[1];

  RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(1, "Could not get path.");
}

# Grab the file version of file mnet.exe

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\mnet.exe", string:path);

NetUseDel(close:FALSE);

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
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}

NetUseDel();

# Check the version number.
if (!isnull(ver))
{
  fixed_version  = "10.1.7.0";
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
          "File              : ", path, "\\mnet.exe\n",
          "Installed version : ", version, "\n", 
          "Fixed version     : ", fixed_version, "\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      exit(0);
   }
    else if (ver[i] > fix[i])
      break;

 exit(0, "mnet.exe version "+version+" is installed and not vulnerable.");
}
else exit(1, "Can't get file version of 'mnet.exe'.");
