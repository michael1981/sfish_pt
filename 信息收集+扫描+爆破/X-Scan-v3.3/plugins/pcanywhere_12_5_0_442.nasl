#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(35976);
  script_version("$Revision: 1.1 $");

  script_cve_id("CVE-2009-0538");
  script_bugtraq_id(33845);
  script_xref(name:"OSVDB", value:"52797");
  script_xref(name:"Secunia", value:"34305");

  script_name(english:"Symantec pcAnywhere CHF File Pathname Format String Denial of Service");
  script_summary(english:"Checks version of awhost32.exe");
 
  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote Windows host has an application that is affected by a local\n",
      "format string vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The version of Symantec pcAnywhere installed on the remote Windows\n",
      "host does not properly handle format strings within remote control\n",
      "file names ('.CHF') or their associated file paths.  Using a specially\n",
      "crafted file or path name, a local user may be able to exploit this\n",
      "issue to read or write arbitrary memory and at a minimum crash the\n",
      "affected application."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.layereddefense.com/pcanywhere17mar.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://archives.neohapsis.com/archives/bugtraq/2009-03/0190.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.symantec.com/avcenter/security/Content/2009.03.17.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Upgrade to pcAnywhere version 12.5.0 Build 442 (also known as 12.5\n",
      "SP1) or later."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P"
  );
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Detect where pcAnywhere is installed.
#
# nb: don't exit if a key isn't found -- we'll check another location later.
list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (isnull(list)) exit(0);
key = NULL;
foreach name (keys(list))
{
  prod = list[name];
  if (prod && prod =~ "^Symantec pcAnywhere")
  {
    key = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(.+)\/DisplayName$", replace:"\1", string:name);
    key = str_replace(find:"/", replace:"\", string:key);
    break;
  }
}


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


# Find the install path.
path = NULL;

if (!isnull(key))
{
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:"InstallLocation");
    if (!isnull(item))
    {
      path = item[1];
      path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
    }

    RegCloseKey(handle:key_h);
  }
}
# - Look in alternate locations if we haven't found it yet.
if (isnull(path))
{
  key = "SOFTWARE\Symantec\InstalledApps";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:"pcAnywhere");
    if (!isnull(item)) 
    {
      path = item[1];
      path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
    }

    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}


# Grab the version and description from the executable.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\awhost32.exe", string:path);
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

ver = NULL;
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}
NetUseDel();


# Check the version number.
#
# nb: Layered Defense says it affects versions 10 through 12.5;
#     Symantec says only 12.0, 12.1, 12.5
#
# who to believe???
if (!isnull(ver) && ver =~ "^(10\.|11\.|12\.[0-5])")
{
  fix = split("12.5.0.442", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity)
      {
        version = string(ver[0], ".", ver[1], ".", ver[2], " Build ", ver[3]);

        report = string(
          "\n",
          "Symantec pcAnywhere ", version, " is installed under :\n",
          "\n",
          "  ", path, "\n"
        );
        security_warning(port:port, extra:report);
      }
      else security_warning(port);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}
