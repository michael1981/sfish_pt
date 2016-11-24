#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(38792);
  script_version("$Revision: 1.3 $");
  
  script_cve_id("CVE-2009-0714");
  script_bugtraq_id(34955);
  script_xref(name:"OSVDB", value:"54509");
  script_xref(name:"milw0rm", value:"9006");
  script_xref(name:"milw0rm", value:"9007");
  script_xref(name:"Secunia", value:"35084");

  script_name(english:"HP Data Protector Express Crafted Traffic Remote Memory Disclosure");
  script_summary(english:"Checks version of dpwinsdr.exe");
 
  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Windows host contains an application that is affected by a
local privilege escalation vulnerability." );

  script_set_attribute(
    attribute:"description", 
    value:
"HP Data Protector Express is installed on the remote host.  The
installed version of the software is affected by an unspecified local
privilege escalation vulnerability.  A local attacker could exploit
this vulnerability to trigger a denial of service condition or execute
arbitrary code with system level privileges. According to reports
this flaw could also be triggered remotely by exploiting a memory 
leak vulnerability, see references for more info." );

  script_set_attribute(
    attribute:"see_also", 
    value:"http://ivizsecurity.com/security-advisory-iviz-sr-09002.html" );

  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?bbd5cf40" );

  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/archive/1/503482" );

  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to HP Data Protector Express Single Server Edition version
3.5 SP2 build 47065 / 4.0 SP1 build 46537 or later." );
  script_set_attribute(
    attribute:"cvss_vector", 
    value: "CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C" );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

#

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

# Find where it's installed.
path = NULL;

key = "SOFTWARE\HP\Data Protector Express";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"RootPath");
  if (!isnull(value)) path = value[1];

  RegCloseKey(handle:key_h);
}

# version 3.5 SP2 path is stored under a subkey 
# SOFTWARE\HP\Data Protector Express\v3.50-sp2

if(isnull(path))
{
  key = "SOFTWARE\HP\Data Protector Express";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

  if (!isnull(key_h))
  {  
    info = RegQueryInfoKey(handle:key_h);
    for (i=0; i<info[1]; ++i) 
    {
      subkey = RegEnumKey(handle:key_h, index:i);
      if (strlen(subkey))
      {   
        key2 = key + "\" + subkey ;
        key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
        if (!isnull(key2_h))
        { 
          value = RegQueryValue(handle:key2_h, item:"RootPath");
          if (!isnull(value)) path = value[1];

          RegCloseKey(handle:key2_h);
        }
      }
    }
    RegCloseKey (handle:key_h);
  }
}

RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0);
}

# Grab the file version of file dpwinsdr.exe

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\dpwinsdr.exe", string:path);

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
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  if(( ver[0] == 3 && ver[1] <  50 ) ||
     ( ver[0] == 3 && ver[1] == 50 && ver[2] < 47065 ) ||
     ( ver[0] == 4 && ver[1] == 0  && ver[2] < 46537 )
    )
    {
      if (report_verbosity > 0)
      {
 	# Make plugin output version inline with
        # solution version.

        if ( ver[0] == 3 && ver[1] == 50 ) ver[1] = 5;

	version = string(ver[0],".",ver[1]," Build ",ver[2]);
        report = string(
          "\n",
          "Version ", version, " of HP Data Protector Express is installed under :\n",
          "\n",
          "  ", path, "\n"
        );
        security_warning(port:port, extra:report);
      }
      else	 
      	security_warning(port);
    }
}
