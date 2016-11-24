#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(12108);
 script_version("$Revision: 1.6 $");

 script_bugtraq_id(9872);
 script_xref(name:"OSVDB", value:"4305");
 script_xref(name:"Secunia", value:"11136");

 script_name(english:"WS_FTP Pro Client ASCII Mode Directory Listing Handling Overflow");
 script_summary(english:"IPSWITCH WS_FTP client overflow detection");

 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "The remote Windows host has an FTP client that is prone to a buffer\n",
   "overflow attack."
  )
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The version of WS_FTP Pro, an FTP client, installed on the remote host\n",
   "is earlier than 9.0.  Such versions are reportedly affected by a\n",
   "remote overflow triggered by an overly long string of ASCII mode\n",
   "directory data from a malicious server.\n",
   "\n",
   "If an attacker can trick a user on this system to connect to a\n",
   "malicious FTP server using the affected application, he may be able to\n",
   "leverage this issue to execute arbitrary code subject to the user's\n",
   "privileges."
  )
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://www.securityfocus.com/archive/1/357438/30/0/threaded"
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://www.securityfocus.com/archive/1/358045/30/0/threaded"
 );
 script_set_attribute(
  attribute:"solution", 
  value:"Upgrade to WS_FTP Pro 9.0, as that reportedly addresses the issue."
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
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

# start script

include("smb_func.inc");
include("smb_hotfixes.inc");

rootfile = hotfix_get_programfilesdir();
if ( ! rootfile ) exit(1);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\WS_FTP\WSFTP32.DLL", string:rootfile);

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
 version = GetFileVersion(handle:handle);
 CloseFile(handle:handle);

 if ( !isnull(version) )
 {
  v = string(version[0], ".", version[1], ".", version[2], ".", version[3]);
  set_kb_item(name:"ws_ftp_client/version", value:v);

  if ( version[0] < 9) 
  {
    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "  Product           : WS_FTP Pro\n",
        "  Path              : ", rootfile, "\\WS_FTP\n",
        "  Installed version : ", v, "\n",
        "  Fix               : 9.0\n"
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
  }
 }
}


NetUseDel();  
