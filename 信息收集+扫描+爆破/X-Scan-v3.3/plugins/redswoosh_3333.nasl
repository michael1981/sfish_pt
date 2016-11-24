#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33126);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2008-1106");
  script_bugtraq_id(29587);
  script_xref(name:"Secunia", value:"30135");
  script_xref(name:"OSVDB", value:"46021");

  script_name(english:"Akamai Red Swoosh < 3333 referer Header Cross-Site Request Forgery");
  script_summary(english:"Checks registry for version of Red Swoosh DLL"); 

 script_set_attribute(attribute:"synopsis", value:
"A remote Windows host contains a program that is affected by a cross-site
request forgery vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Akamai Red Swoosh client, which handles
software distribution via the Swoosh network. 

The version of Red Swoosh installed on the remote host includes a web
server that listens on the loopback interface for management commands
and that fails to properly sanitize the HTTP Referer header.  By
tricking a user on the affected host into visiting a specially-crafted
web page, an attacker can leverage this issue to cause files from
arbitrary URLs to be downloaded and executed on the remote host
subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2008-19/advisory/" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/493170/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Update to Red Swoosh version 3333 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
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


# Make sure the Akamai service is running, unless we're being paranoid.
if (report_paranoia < 2)
{
  services = get_kb_item("SMB/svcs");
  if (!services || "Akamai" >!< services) exit(0);
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


# Find the service dll.
dll = NULL;

key = "SYSTEM\CurrentControlSet\Services\Akamai\Parameters";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"ServiceDll");
  if (!isnull(value)) dll = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(dll))
{
  NetUseDel();
  exit(0);
}


# Make sure the dll exists.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:dll);
dll2 =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:dll);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:dll2,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
version = NULL;
if (!isnull(fh))
{
  CloseFile(handle:fh);

  # Take the version number from the filename itself.
  version = ereg_replace(pattern:"^.+rswin_([0-9]+)\.dll$", replace:"\1", string:dll);
}
NetUseDel();


# Check the version number.
if (!isnull(version))
{
  if (int(version) < 3333)
  {
    if (report_verbosity)
    {
      path = ereg_replace(pattern:"^(.+)\\rswin_[0-9]+\.dll$", replace:"\1", string:dll);
      report = string(
        "\n",
        "Akamai Red Swoosh version ", version, " is installed under :\n",
        "\n",
        "  ", path, "\n"
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    set_kb_item(name: 'www/0/XSS', value: TRUE);	# Maybe integrist...
  }
}
