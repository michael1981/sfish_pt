#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11928);
 script_version("$Revision: 1.18 $");

 script_cve_id("CVE-2003-0711");
 script_bugtraq_id(8828);
 script_xref(name:"OSVDB", value:"11462");
 
 name["english"] = "MS03-044: Buffer Overrun in Windows Help (825119)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the Help
service." );
 script_set_attribute(attribute:"description", value:
"A security vulnerability exists in the Windows Help Service that could
allow arbitrary code execution on an affected system.  An attacker who
successfully exploited this vulnerability could run code with Local
System privileges on this host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000, XP and
2003 :

http://www.microsoft.com/technet/security/bulletin/ms03-044.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Checks for hotfix 825119";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 script_dependencies("smb_hotfixes.nasl");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( hotfix_missing(name:"896358") == 0 ) exit(0);

# Ignore Vista / Windows 2008 -- they're not affected.
os = get_kb_item("SMB/WindowsVersion");
if ( os && os == "6.0" ) exit(0);

rootfile = hotfix_get_systemroot();
if  ( ! rootfile ) exit(1);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
itircl =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\system32\itircl.dll", string:rootfile);


port = kb_smb_transport();
if ( ! get_port_state(port) ) exit(1);

soc = open_sock_tcp(port);
if ( ! soc ) exit(1);

session_init(socket:soc, hostname:kb_smb_name());
r = NetUseAdd(login:kb_smb_login(), password:kb_smb_password(), domain:kb_smb_domain(), share:share);
if ( r != 1 ) exit(1);

handle =  CreateFile (file:itircl, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);


if ( ! isnull(handle) )
{
 v = GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if ( ! isnull(v) ) 
 {
  if ( v[0] < 5 ||
       ( v[0] == 5 && v[1] < 2) ||
       ( v[0] == 5 && v[1] == 2 && v[2] < 3790 ) ||
       ( v[0] == 5 && v[1] == 2 && v[2] == 3790 && v[3] < 80 )) {
 set_kb_item(name:"SMB/Missing/MS03-044", value:TRUE);
 hotfix_security_hole();
 }
 }
 else {
 NetUseDel();
 exit(1);
 }
}

NetUseDel();
