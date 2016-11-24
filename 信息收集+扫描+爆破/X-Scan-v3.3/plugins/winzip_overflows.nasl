#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(17362);
  script_cve_id("CVE-2004-1465");
  script_bugtraq_id(11092);
  script_xref(name:"OSVDB", value:"9511");
  script_version("$Revision: 1.7 $");

  script_name(english:"WinZip Multiple Overflows");
  script_summary(english:"Determines the presence of WinZip");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote version of WinZip is vulnerable to multiple buffer overflows.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote host is using a version of WinZip which is older than
version 9.0-SR1.

WinZip is a popular ZIP compression tool. The remote version of this
software contains several buffer overflows which may allow an attacker
to execute arbitrary code on the remote host.

To exploit it, an attacker would need to send a malformed archive
file to a user on the remote host and wait for him to open it
using WinZip."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Upgrade to WinZip 9.0-SR1 or later."
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.winzip.com/wz90sr1.htm'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_family(english:"Windows");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}


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

if(!get_port_state(port))exit(1);
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


# Determine where it's installed.
path = NULL;

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{CD95F661-A5C4-44F5-A6AA-ECDD91C240B6}";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
 item = RegQueryValue(handle:key_h, item:"InstallLocation");
 if (!isnull(item))
    path = item[1];

 RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0);
}



share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\WinZip32.exe", string:path);


NetUseDel(close:FALSE);

r = NetUseAdd(share:share);
if ( r != 1 )
{
 NetUseDel();
 exit(1);
}

handle = CreateFile (file:exe, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

if ( ! isnull(handle) )
{
 version = GetFileVersion (handle:handle);
 CloseFile(handle:handle);
 if ( isnull(version) )
	{
	 NetUseDel();
	 exit(1);
	}

 # Version 9.0.0 SR-1 is version 18.0.6224.0
 set_kb_item(name:"SMB/WinZip/Version", value:version[0] + "." + version[1] + "." + version[2] + "." + version[3]);
 if ( version[0] < 18 || ( version[0] == 18  && version[1] == 0 && version[2] < 6224) )
	security_note( port );

}

NetUseDel();
