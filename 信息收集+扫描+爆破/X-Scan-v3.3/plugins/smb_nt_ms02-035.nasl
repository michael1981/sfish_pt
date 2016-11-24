#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11322);
 script_version("$Revision: 1.22 $");

 script_cve_id("CVE-2002-0643");
 script_bugtraq_id(5203);
 script_xref(name:"OSVDB", value:"10141");

 script_name(english:"MS02-035: MS SQL Installation may leave passwords on system (263968)");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to get the remote SQL Server's administrator
password." );
 script_set_attribute(attribute:"description", value:
"The installation process for the remote MS SQL Server left files
named 'setup.iss' on the remote host.  These files contain the
password assigned to the 'sa' account of the remote database. 

An attacker who manages to view these files may be able to leverage
this issue to gain full administrative access to the application." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for SQL Server 7 and 2000 :

http://www.microsoft.com/technet/security/bulletin/ms02-035.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Reads %windir%\setup.iss");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/registry_access");
 script_require_ports(139, 445);
 exit(0);
}

#

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");



rootfile = hotfix_get_systemroot();
if ( ! rootfile ) exit(1);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
rootfile =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\setup.iss", string:rootfile);


port    = kb_smb_transport();
if(!get_port_state(port))exit(1);

soc = open_sock_tcp(port);
if(!soc)exit(1);


session_init(socket:soc, hostname:kb_smb_name());
r = NetUseAdd(login:kb_smb_login(), password:kb_smb_password(), domain:kb_smb_domain(), share:share);
if ( r != 1 ) exit(1);

foreach file (make_list("MSSQL7\Install\setup.iss", rootfile))
{
 handle =  CreateFile (file:file, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

 if ( ! isnull(handle) ) 
 {
  resp = ReadFile(handle:handle, length:16384, offset:0);
  CloseFile(handle:handle);
  if("svPassword=" >< resp){
	 {
 set_kb_item(name:"SMB/Missing/MS02-035", value:TRUE);
 hotfix_security_warning();
 }
	NetUseDel();
	exit(0);
	}
 }
}

NetUseDel();
