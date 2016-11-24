#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(17656);
 script_version("$Revision: 1.12 $");

 script_cve_id("CVE-2002-1442", "CVE-2002-1444", "CVE-2004-2475");
 script_bugtraq_id(5424, 5477, 11210);
 script_xref(name:"OSVDB", value:"7898");
 script_xref(name:"OSVDB", value:"10036");
 script_xref(name:"OSVDB", value:"10037");

 script_name(english:"Google Toolbar < 2.0.114.1 Multiple Vulnerabilities");
 script_summary(english:"Checks the version of Google Toolbar"); 
 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an ActiveX control that is affected by an HTML
injection vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the Google Toolbar, a toolbar of Internet
Explorer.

The remote version of this software is reportedly affected by an HTML
injection vulnerability which may allow an attacker to execute a
cross-site scripting attack." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2002-08/0133.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-09/0226.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Google Toolbar 2.0.114.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

#

include("smb_func.inc");
include("smb_hotfixes.inc");

name 	=  kb_smb_name();
login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();

if(!get_port_state(port))exit(1);
soc = open_sock_tcp(port);
if(!soc)exit(1);

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


path = NULL;
key = "SOFTWARE\Google\Google Toolbar\Brokers\CLSID";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
 info = RegQueryInfoKey(handle:key_h);
 for (i=0; i<info[0]; ++i) 
 {
  value = RegEnumValue(handle:key_h, index:i);
  if (!isnull(value))
  {
    subkey = value[1];
    item = RegQueryValue(handle:key_h, item:subkey);
    if (!isnull(item)) 
    {
     path = item[1];
     break;
    }
  }
 }
}

RegCloseKey(handle:hklm);

if (!path)
{
 NetUseDel();
 exit(0);
}

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:path);

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

 set_kb_item(name:"SMB/Google/Toolbar/Version", value:version[0] + "." + version[1] + "." + version[2] + "." + version[3]);

 if ( version[0] < 2 || ( version[0] == 2  && version[1] == 0 && version[2] < 114) || (version[0] == 2 && version[1] == 0 && version[2] == 114 && version[3] <= 1 ) )
	security_hole ( port );

}

NetUseDel();
