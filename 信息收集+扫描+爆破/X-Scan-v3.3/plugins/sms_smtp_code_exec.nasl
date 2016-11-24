#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(24755);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2007-1252");
  script_bugtraq_id(22782);
  script_xref(name:"OSVDB", value:"33840");

  script_name(english:"Symantec Mail Security for SMTP Message Handling Arbitrary Code Execution");
  script_summary(english:"Checks version of SMS for SMTP");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that may allow
arbitrary code execution." );
 script_set_attribute(attribute:"description", value:
"Symantec Mail Security for SMTP, which provides anti-spam and anti-
virus protection for the IIS SMTP Service, is installed on the remote
Windows host. 

There is reportedly an issue with the version of Symantec Mail
Security for SMTP on the remote host that can be triggered by messages
with malformed headers and lead to a crash or arbitrary code
execution. 

Note that successful exploitation of this issue would allow an
attacker to gain complete control of the affected host as Symantec
Mail Security for SMTP runs with LOCAL SYSTEM privileges by default." );
 script_set_attribute(attribute:"see_also", value:"http://www.kb.cert.org/vuls/id/875633" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e22007ca" );
 script_set_attribute(attribute:"solution", value:
"Upgrade as necessary to Symantec Mail Security for SMTP 5.0 and apply
patch 175 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Make sure the SMS for SMTP service is running, unless we're 
# being paranoid.
if (report_paranoia < 2)
{
  services = get_kb_item("SMB/svcs");
  if (
    !services ||
    ("SMSTomcat" >!< services && "Symantec Mail Security for SMTP" >!< services)
  ) exit(0);
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


# Find where it's installed.
path = NULL;
key = "SOFTWARE\Symantec\SMSSMTP";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"LoadPoint");
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
  exit(0);
}


# Grab the product version from the BrightmailVersion class file.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
class =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\tomcat\webapps\brightmail\WEB-INF\classes\com\brightmail\util\BrightmailVersion.class", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:class,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (!isnull(fh))
{
  # nb: limit how much we'll read.
  fsize = GetFileSize(handle:fh);
  if (fsize > 10000) fsize = 10000;

  # nb: the string should be around 1500 so this should
  #     succeed after just one read.
  chunk = 2048;
  ofs = 0 ;
  ver = NULL;
  while (fsize > 0 && ofs <= fsize)
  {
    data = ReadFile(handle:fh, length:chunk, offset:ofs);
    if (strlen(data) == 0) break;
    data = str_replace(find:raw_string(0), replace:"", string:data);
    if ("Name: smssmtp" >< data && data =~ "Name: smssmtp[0-9_-]+ ")
      ver = ereg_replace(pattern:"^.+Name: smssmtp([0-9_-]+) .*$", replace:"\1", string:data);
    if (isnull(ver)) ofs += chunk;
    else break;
  }
  CloseFile(handle:fh);

  # nb: Patch 175 is reported as "500-2007-02-09_02" by, eg,
  #     https://target:41443/brightmail/BrightmailVersion
  if (!isnull(ver))
  {
    if (ver =~ "^([0-4]|500-(1|200[0-6]|2007-(01|02-0[0-8]|02-09_0[01])))")
    {
      report = string(
        "\n",
        "Symantec Mail Security for SMTP version ", ver, " is\n",
        "installed under :\n",
        "\n",
        "  ", path, "\n"
      );
      security_hole(port:port, extra:report);
    }
  }
}


# Clean up.
NetUseDel();
