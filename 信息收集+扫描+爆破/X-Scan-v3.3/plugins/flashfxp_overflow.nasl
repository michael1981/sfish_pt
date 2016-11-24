#
# (C) Tenable Network Security, Inc.
#
# 


include("compat.inc");


if(description)
{
 script_id(11710);
 script_version("$Revision: 1.9 $");
 script_bugtraq_id(7857, 7859);
 script_xref(name:"Secunia", value:"8977");
 script_xref(name:"OSVDB", value:"59041");
 script_xref(name:"OSVDB", value:"59042");

 script_name(english:"FlashFXP < 2.1b923 Multiple Remote Overflows");
 script_summary(english:"Determines the presence of FlashFXP");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "An FTP client with multiple stack buffer overflow vulnerabilities is\n",
     "installed on the remote Windows host."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "FlashFXP, an FTP client, is installed on the remote host.  This\n",
     "version is vulnerable to a stack buffer overflow attack when receiving\n",
     "a long response to the PASV command, or when processing a long host\n",
     "name."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.securityfocus.com/archive/1/324387"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to FlashFXP 2.1 build 923 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
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

#

include("smb_func.inc");
include("smb_hotfixes.inc");

rootfile = hotfix_get_programfilesdir();
if ( ! rootfile ) exit(1);
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\FlashFXP\FlashFXP.exe", string:rootfile);



name 	=  kb_smb_name();
login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();
if(!get_port_state(port))exit(1);
soc = open_sock_tcp(port);
if(!soc)exit(1);


session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 ) exit(1);

fid = CreateFile(file:exe);
if ( isnull( fid ))
{
 NetUseDel();
 exit(0);
}


version = GetFileVersion (handle:fid);
CloseFile(handle:fid);
NetUseDel();

if( isnull(version) )exit(1);
if ( version[0] < 2 || (version[0] == 2 && version[1] == 0 ) ) security_hole(port);
