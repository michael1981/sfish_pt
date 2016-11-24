#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(18049);
 script_version("$Revision: 1.11 $");

 script_cve_id("CVE-2005-1168", "CVE-2005-1185");
 script_bugtraq_id(13167, 13173, 13174);
 script_xref(name:"OSVDB", value:"15624");
 script_xref(name:"OSVDB", value:"15806");
 script_xref(name:"Secunia", value:"15087");

 script_name(english:"MusicMatch < 9.0.5066 / 10.0.2048 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a media player that is affected by multiple
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running MusicMatch, a music player.

The remote version of this software is affected by a buffer overflow
vulnerability as well as a cross-site scripting vulnerability. 

An attacker may exploit these flaws to execute arbitrary code on
the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.musicmatch.com/info/user_guide/faq/security_updates.htm" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-04/0210.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MusicMatch 9.0.5066 or 10.0.2048." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );

 script_end_attributes();

 script_summary(english:"Checks for the version of MusicMatch");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

# start script

include("smb_func.inc");
include("smb_hotfixes.inc");

if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(1);
name = kb_smb_name();
port = kb_smb_transport();
if(!get_port_state(port)) exit(1);
login = kb_smb_login();
pass  = kb_smb_password();
domain = kb_smb_domain();
          
soc = open_sock_tcp(port);
if(!soc) exit(1);

session_init(socket:soc, hostname:name);

r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(1);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
 NetUseDel();
 exit(1);
}

key = "SOFTWARE\MusicMatch\MusicMatch JukeBox";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( isnull(key_h) )
{
 RegCloseKey(handle:hklm);
 NetUseDel();
 exit(0);
}

info = RegQueryInfoKey(handle:key_h);
for ( i = 0 ; i < info[1] ; i ++ )
{
 entries[i] = RegEnumKey(handle:key_h, index:i);
}

RegCloseKey(handle:key_h);
RegCloseKey(handle:hklm);
NetUseDel();

max_version[0] = max_version[1] = max_version[2] = 0;

foreach entry (entries)
{
 if ( ereg(pattern:"[0-9]*\.[0-9]*\.[0-9]*", string:entry) )
 {
  version = split(entry, sep:'.', keep:0);
  if ( int(version[0]) > int(max_version[0]) ||
       (int(version[0]) == int(max_version[0]) && int(version[1]) > int(max_version[1])) ||
       (int(version[0]) == int(max_version[0]) && int(version[1]) == int(max_version[1]) && int(version[2]) > int(max_version[2])) 
     )
	{
	 max_version[0] = version[0];
	 max_version[1] = version[1];
	 max_version[2] = version[2];
	}
 }
}

if ( max_version[0] < 9 )
{
 security_warning(0); # Versions older than 9.x were not patched
 set_kb_item(name: 'www/0/XSS', value: TRUE);
}
else if ( max_version[0] == 9 && max_version[2] < 5066 )
{
 security_warning(port); # < 9.0.5066
 set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}
else if ( max_version[0] == 10 && max_version[2] < 2048)
{
 security_warning(port); # < 10.0.2048
 set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}

set_kb_item(name:"SMB/MusicMatch/Version", value:max_version[0] + "." + max_version[1] + "." + max_version[2]);

