#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11616);
 script_version("$Revision: 1.7 $");
 script_bugtraq_id(7040);
 script_xref(name:"OSVDB", value:"58839");

 script_name(english:"DBTools DBManager catalog.mdb Cleartext Local Credential Disclosure");
 script_summary(english:"Determines the presence of DBManager.exe");

 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The database manager on the remote host has an information disclosure\n",
     "vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is running DBManager from DBTool - a GUI to manage\n",
     "MySQL and PostgreSQL databases.\n\n",
     "This program stores the passwords and IP addresses of the managed\n",
     "databases in an unencrypted file.  A local attacker could use the data\n",
     "in this file to log into the managed databases and execute arbitrary\n",
     "SQL queries."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2003-03/0128.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"There is no solution at this time."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Databases");
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

#

include("smb_func.inc");
include("smb_hotfixes.inc");

rootfile = hotfix_get_programfilesdir();
if ( ! rootfile ) exit(0);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\DBTools Software\DBManager Professional\DBManager.exe", string:rootfile);



name 	= kb_smb_name();
login	= kb_smb_login();
pass  	= kb_smb_password();
domain 	= kb_smb_domain();
port    = kb_smb_transport();

if(!get_port_state(port))exit(1);
soc = open_sock_tcp(port);
if(!soc)exit(1);


session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 ) exit(1);


handle = CreateFile (file:exe, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if( ! isnull(handle) )
{
 security_note(port);
 CloseFile(handle:handle);
}

NetUseDel();
