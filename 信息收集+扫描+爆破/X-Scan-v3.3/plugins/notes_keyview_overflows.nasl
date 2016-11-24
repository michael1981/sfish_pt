#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(27534);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2007-4222", "CVE-2007-5909", "CVE-2007-5910");
  script_bugtraq_id(26175, 26200);
  script_xref(name:"OSVDB", value:"40783");
  script_xref(name:"OSVDB", value:"40786");
  script_xref(name:"OSVDB", value:"40787");
  script_xref(name:"OSVDB", value:"40788");
  script_xref(name:"OSVDB", value:"40789");
  script_xref(name:"OSVDB", value:"40790");
  script_xref(name:"OSVDB", value:"40791");
  script_xref(name:"OSVDB", value:"40792");
  script_xref(name:"OSVDB", value:"40949");

  script_name(english:"Lotus Notes Client < 7.0.3 / 8.0.1 Multiple Overflows");
  script_summary(english:"Checks version of Lotus Notes"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by several
buffer overflow vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of Lotus Notes installed on the remote Windows host is
reportedly affected by several buffer overflows in its file attachment
viewer when handling attachments of various types.  By sending a
specially-crafted attachment to users of the affected application and
getting them to double-click and view the attachment, an attacker may
be able to execute arbitrary code subject to the privileges under
which the affected application runs. 

It is also affected by another buffer overflow vulnerability in the
TagAttributeListCopy function in ''nnotes.dll'' that could be
triggered when a specially-crafted message is replied to, forwarded,
or copied to the clipboard by a user of the application." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/482664/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg21271111" );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg21272836" );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=604" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/482738" );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg21272930" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Lotus Notes version 7.0.3 / 8.0.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/name", "SMB/login", "SMB/password");
  script_require_ports("Services/notes", 139, 445);
  exit(0);
}

#

include("smb_func.inc");


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
if (rc != 1) exit(0);


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}


# Determine where it's installed.
path = NULL;

key = "SOFTWARE\Lotus\Notes";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  value = RegQueryValue(handle:key_h, item:"Path");
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


# Determine the version of the Notes client.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\notes.exe", string:path);
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
if (isnull(fh))
{
  NetUseDel();
  exit(0);
}
ver = GetFileVersion(handle:fh);
CloseFile(handle:fh);
NetUseDel();


# If it's an affected version...
#
# nb: ver[2] is multiplied by 10.
if (
  (int(ver[0]) == 6 && int(ver[1]) == 5) ||
  (int(ver[0]) == 7 && int(ver[1]) == 0 && int(ver[2]) < 30) ||
  (int(ver[0]) == 8 && int(ver[1]) == 0 && int(ver[2]) < 10)
) security_hole(port);
