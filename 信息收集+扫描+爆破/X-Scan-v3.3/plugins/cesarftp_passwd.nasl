#
# (C) Tenable Network Security, Inc.
#
# Ref:
#  From: "Andreas Constantinides" <megahz@megahz.org>
#  To: <bugtraq@securityfocus.com>
#  Subject: Plaintext Password in Settings.ini of CesarFTP
#  Date: Tue, 20 May 2003 10:25:56 +0300


include("compat.inc");


if(description)
{
 script_id(11640);
 script_cve_id("CVE-2001-1336", "CVE-2003-0329");
 script_xref(name:"OSVDB", value:"12056");
 
 script_version("$Revision: 1.10 $");

 script_name(english:"CesarFTP settings.ini Authentication Credential Cleartext Disclosure");
 script_summary(english:"Determines the presence of CesarFTP's settings.ini");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote FTP server is storing unencrypted passwords on disk."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
      "The remote host is running CesarFTP.\n\n",
      "Due to a design flaw in the program, the cleartext usernames and\n",
      "and passwords of FTP users are stored in the file 'settings.ini'.\n",
      "Any user with an account on this host may read this file and use the\n",
      "password to connect to this FTP server."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2001-05/0252.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2003-05/0211.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"There is no known solution at this time."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");

rootfile = hotfix_get_programfilesdir();
if ( ! rootfile ) exit(0);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\CesarFTP\Settings.ini", string:rootfile);


name 	=  kb_smb_name();
login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 ) exit(0);

handle = CreateFile (file:exe, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if( ! isnull(handle) )
{
 data = ReadFile(handle:handle, length:16384, offset:0);
 if('Password= "' >< data && 'Login= "' >< data) security_note(port);
 CloseFile(handle:handle);
}

NetUseDel();

