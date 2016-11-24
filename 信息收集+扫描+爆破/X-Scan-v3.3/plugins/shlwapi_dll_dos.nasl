#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11583);
 script_version("$Revision: 1.10 $");
 script_bugtraq_id(7402);
 script_xref(name:"OSVDB", value:"11936");

 script_name(english:"Microsoft Windows shlwapi.dll Malformed HTML Tag Handling Null Pointer DoS");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to crash the remote web client." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the shlwapi.dll which crashes
when processing a malformed HTML form.

An attacker may use this flaw to prevent the users of this host from
working properly.

To exploit this flaw, an attacker would need to send a malformed
HTML file to the remote user, either by e-mail or by making him
visit a rogue web site." );
 script_set_attribute(attribute:"solution", value:
"None" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 script_summary(english:"Checks for the version of shlwapi.dll");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_exclude_keys("SMB/samba");
 script_require_ports(139, 445);
 exit(0);
}

#

include("smb_func.inc");
include("smb_hotfixes.inc");


rootfile = hotfix_get_systemroot();
if ( ! rootfile ) exit(1);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\System32\shlwapi.dll", string:rootfile);



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
 

handle = CreateFile (file:file, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if ( ! isnull(handle) )
{
 v = GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if ( ! isnull(v) )
 {
  if ( v[0] < 6 || (v[0] == 6 && v[1] == 0 && (v[2] < 2800 || ( v[2] == 2800 && v[3] < 1106 ) ) ) ) 
	security_warning( port );
 }
 else {
	NetUseDel();
	exit(1);
      }
}

NetUseDel();
