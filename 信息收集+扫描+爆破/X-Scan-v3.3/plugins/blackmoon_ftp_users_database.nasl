#
# (C) Tenable Network Security, Inc.
#
# Ref: http://marc.info/?l=bugtraq&m=105353283720837&w=2


include("compat.inc");


if(description)
{
 script_id(11649);
 script_bugtraq_id(7646);
 script_cve_id("CVE-2003-0342");
 script_xref(name:"Secunia",value:"8840"); 
 script_xref(name:"OSVDB", value:"12078");
 
 script_version("$Revision: 1.11 $");

 script_name(english:"BlackMoon FTP Server blackmoon.mdb Cleartext Password Disclosure");
 script_summary(english:"Determines the presence of Blackmoon ftp users database");

 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote FTP server is affected by a password disclosure vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "BlackMoon FTP server is installed on the remote host.  FTP usernames\n",
     "and passwords are stored on the server in cleartext in\n",
     "a filed called 'blackmoon.mdb.'  Any user with an account on this\n",
     "host may read the credentials stored in this file, and use them to\n",
     "connect to this FTP server."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://marc.info/?l=bugtraq&m=105353283720837&w=2"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of BlackMoon FTP."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:L/AC:L/Au:S/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 
 script_dependencies( "smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");

 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");

rootfile = hotfix_get_programfilesdir();
if  ( ! rootfile ) exit(0);

name 	=  kb_smb_name();
login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();
if(!get_port_state(port))exit(0);


share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Selom Ofori\BlackMoon FTP Server\blackmoon.mdb", string:rootfile);


soc = open_sock_tcp(port);
if(!soc)exit(0);

session_init(socket:soc, hostname:name);

r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 ) exit(0);

handle = CreateFile (file:exe, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if(! isnull(handle) )
{
 data = ReadFile(handle:handle, length:16384, offset:0);
 if("Standard Jet DB" >< data) security_warning(port);
 CloseFile(handle:handle);
}

NetUseDel();
