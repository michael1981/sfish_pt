#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description) 
{
  script_id(39563);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-1394");
  script_bugtraq_id(35496);
  script_xref(name:"OSVDB", value:"55436");

  script_name(english:"Timbuktu Pro < 8.6.7 PlughNTCommand Named Pipe Remote Stack Buffer Overflow");
  script_summary(english:"Checks version of tb2pro.exe"); 
 
  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote Windows host contains a program that is prone to a remote\n",
      "buffer overflow attack."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote Windows host contains a version of Motorola Inc.'s Timbuktu\n",
      "Pro that is earlier than 8.6.7.  Timbuktu Pro allows remote access to\n",
      "a computer's desktop, and versions before 8.6.7 reportedly contain a\n",
      "stack buffer overflow that can be triggered when the 'PlughNTCommand'\n",
      "named pipe receives an overly large character string.  An\n",
      "unauthenticated remote attacker can leverage this issue to crash the\n",
      "affected application or to execute arbitrary code with SYSTEM\n",
      "privileges."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=809"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/archive/1/504554/30/0/threaded"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?41cf5a58"
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Upgrade to Timbuktu Pro for Windows version 8.6.7 or later."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:string(
      "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
    )
  );
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


# Connect to the appropriate share.
if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);
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


# Check whether it's installed.
path = NULL;

key = "SOFTWARE\Netopia\Timbuktu Pro";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"InstallPath");
  if (!isnull(value))
  {
    path = value[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  }

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0, "Timbuktu Pro is not installed.");
}


# Check the version of the main exe.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\tb2pro.exe", string:path);
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
  version = string(ver[0], ".", ver[1], ".", ver[2]);

  fix = split("8.6.7.1379", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity > 0)
      {
        report = string(
          "\n",
          "  Version : ", version, "\n",
          "  Path    : ", path, "\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      exit(0);
    }
    else if (ver[i] > fix[i])
      break;

  exit(0, "Timbuktu Pro version "+version+" is installed and not vulnerable.");
}
else exit(1, "Couldn't get file version of '"+exe+"'.");
