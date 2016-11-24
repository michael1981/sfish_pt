#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(32394);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2008-2400");
  script_bugtraq_id(29285);
  script_xref(name:"Secunia", value:"30297");
  script_xref(name:"OSVDB", value:"45354");

  script_name(english:"Stunnel < 4.23 Local Privilege Escalation");
  script_summary(english:"Checks version of stunnel.exe"); 

 script_set_attribute(attribute:"synopsis", value:
"A remote Windows host contains a program that is affected by a local
privilege escalation vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Stunnel, an application for encrypting
arbitrary network connections with SSL. 

The version of Stunnel installed on the remote host, when running as a
service, reportedly allows a local user to gain LocalSystem privileges
due to an as-yet unspecified error." );
 script_set_attribute(attribute:"see_also", value:"http://www.stunnel.org/news/" );
 script_set_attribute(attribute:"see_also", value:"http://stunnel.mirt.net/pipermail/stunnel-announce/2008-May/000034.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Stunnel version 4.23 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Make sure the Stunnel service is running, unless we're being paranoid.
if (report_paranoia < 2)
{
  services = get_kb_item("SMB/svcs");
  if (!services || "stunnel" >!< services) exit(0);
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
if (rc != 1)
{
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


# Determine where it's installed.
path = NULL;

key = "SOFTWARE\NSIS_stunnel";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Install_Dir");
  if (!isnull(value)) path = value[1];

  RegCloseKey(handle:key_h);
}
if (isnull(path))
{
  key = "SYSTEM\CurrentControlSet\Services\stunnel";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:"ImagePath");
    if (!isnull(value))
    {
      path = value[1];
      path = ereg_replace(pattern:'^"(.+)\\\\stunnel\\.exe".*', replace:"\1", string:path);
    }

    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  exit(0);
}


# Grab the version from stunnel.exe.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\stunnel.exe", string:path);
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
version = NULL;
if (!isnull(fh))
{
  fsize = GetFileSize(handle:fh);
  if (fsize < 90000) off = 0;
  else off = fsize - 90000;

  while (fsize > 0 && off <= fsize && isnull(version))
  {
    data = ReadFile(handle:fh, length:16384, offset:off);
    if (strlen(data) == 0) break;
    data = str_replace(find:raw_string(0), replace:"", string:data);

    while (strlen(data) && "stunnel " >< data)
    {
      data = strstr(data, "stunnel ") - "stunnel ";
      blob = data - strstr(data, '\n');

      pat = "^([0-9]+\.[^ ]+) on [^ ]+ming.*$";
      if (ereg(pattern:pat, string:blob))
      {   
        version = ereg_replace(pattern:pat, replace:"\1", string:blob);
      }
      if (version) break;
    }
    off += 16383;
  }
  CloseFile(handle:fh);
}
NetUseDel();


# Check the version number.
if (!isnull(version))
{
  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fix = split("4.23", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity)
      {
        report = string(
          "\n",
          "Stunnel version ", version, " is installed under :\n",
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
