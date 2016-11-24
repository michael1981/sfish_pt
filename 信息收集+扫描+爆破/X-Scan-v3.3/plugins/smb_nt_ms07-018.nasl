#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(25026);
 script_cve_id("CVE-2007-0938", "CVE-2007-0939");
 script_bugtraq_id(22860, 22861);
 script_xref(name:"OSVDB", value:"34006");
 script_xref(name:"OSVDB", value:"34007");
 script_version("$Revision: 1.9 $");
 name["english"] = "MS07-018: Vulnerabilities in Microsoft Content Management Server Could Allow Remote Code Execution (925939)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"A remote user can execute arbitrary code on the remote host" );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Microsoft Content Management Server 
which is vulnerable to a security flaw which may allow a remote user to execute
arbitrary code by sending a specially malformed HTTP request." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for MCMS SP1 and SP2 :

http://www.microsoft.com/technet/security/bulletin/ms07-018.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Checks the remote file version for 925939";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");







if ( ! get_kb_item("SMB/WindowsVersion") ) exit(1);
if ( ! hotfix_check_iis_installed() ) exit(1);


rootfile = hotfix_get_programfilesdir();
if ( ! rootfile ) exit(1);

dll  =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft Content Management Server\server\bin\AEServerObject.dll", string:rootfile);
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);

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


handle =  CreateFile (file:dll, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

if ( ! isnull(handle) )
{
 v = GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if ( !isnull(v) ) 
  {
  	 if ( ( v[0] == 5 &&  v[1] == 0 && v[2] < 5317 )  ||
	      ( v[0] == 4 &&  v[1] == 10 && v[2] < 1157) ) {
 set_kb_item(name:"SMB/Missing/MS07-018", value:TRUE);
 hotfix_security_hole();
 }
  }
}

NetUseDel();
