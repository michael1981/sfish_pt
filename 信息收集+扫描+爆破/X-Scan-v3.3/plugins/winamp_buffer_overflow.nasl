#
# (C) Tenable Network Security, Inc.
#

# Ref:
#  Date: Sat, 4 Jan 2003 05:00:47 -0800
#  From: D4rkGr3y <grey_1999@mail.ru>
#  To: bugtraq@securityfocus.com, submissions@packetstormsecurity.com,
#        vulnwatch@vulnwatch.org
#  Subject: [VulnWatch] WinAmp v.3.0: buffer overflow



include("compat.inc");

if(description)
{
 script_id(11530);
 script_version("$Revision: 1.12 $");
 script_cve_id("CVE-2003-1272", "CVE-2003-1273", "CVE-2003-1274");
 script_bugtraq_id(6515, 6516, 6517);
 script_xref(name:"OSVDB", value:"34427");
 script_xref(name:"OSVDB", value:"34428");
 script_xref(name:"OSVDB", value:"34429");

 script_name(english:"Winamp < 3.0b Multiple File Handling DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application affected by multiple
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is using Winamp3, a popular media player which handles
many files format (mp3, wavs and more...)

This version suffers from multiple buffer overflow and denial of
service issues that can be triggered by specially-crafted b4s files. 
To perform an attack, the attack would have to send a malformed
playlist (.b4s) to the user of this host who would then have to load
it by double clicking on it. 

Note that since .b4s are XML-based files, most antivirus programs will
let them in." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2003-01/0025.html" );
 script_set_attribute(attribute:"see_also", value:"http://forums.winamp.com/showthread.php?postid=823240" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Winamp 3.0b or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Determines the version of Winamp");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

#

include("smb_func.inc");
include("smb_hotfixes.inc");

rootfile = hotfix_get_programfilesdir();
if ( ! rootfile ) exit(1);
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
winamp3 =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\WinAmp3\studio.exe", string:rootfile);


name 	=  kb_smb_name();
login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();


if(!get_port_state(port))exit(1);
soc = open_sock_tcp(port);
if( ! soc )exit(1);


session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 ) exit(1);

handle = CreateFile (file:winamp3, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

if ( !isnull(handle) )
{
 version = GetFileVersion(handle:handle);
 if ( isnull(version) )
 {
  NetUseDel();
  exit(1);
 }

 if ( version[0] == 1 && version[1] == 0 && version[2] == 0 && version[3] <= 488 )
	security_hole(port);

 CloseFile(handle:handle);
}


NetUseDel();
