#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(22189);
 script_version("$Revision: 1.11 $");

 script_cve_id("CVE-2006-3649");
 script_bugtraq_id(19414);
 script_xref(name:"OSVDB", value:"27849");

 name["english"] = "MS06-047: Vulnerability in Microsoft Visual Basic for Applications Could Allow Remote Code Execution (921645)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through VBA." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Visual Basic for
Applications that is vulnerable to a buffer overflow when handling
malformed documents. 

An attacker may exploit this flaw to execute arbitrary code on this
host, by sending a malformed file to a user of the remote host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office :

http://www.microsoft.com/technet/security/bulletin/ms06-047.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 summary["english"] = "Determines the version of vbe6.dll";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");

 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


common = hotfix_get_commonfilesdir();
if ( ! common ) exit(1);



#VBA 6- C:\Program Files\Common Files\Microsoft Shared\VBA\VBA6\vbe6.dll = 6.4.99.72
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:common);
vba6 =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft Shared\VBA\VBA6\vbe6.dll", string:common);

port = kb_smb_transport();
if ( ! port ) exit(1);

soc = open_sock_tcp(port);
if ( ! soc ) exit(1);

session_init(socket:soc, hostname:kb_smb_name());
r = NetUseAdd(login:kb_smb_login(), password:kb_smb_password(), domain:kb_smb_domain(), share:share);
if ( r != 1 ) exit(1);

handle = CreateFile (file:vba6, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

if ( ! isnull(handle) )
{
 v = GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if ( ! isnull(v) ) 
 {
 if ( v[0] == 6 && ( v[1] < 4 || ( v[1] == 4 && v[2] < 99 ) || ( v[1] == 4 && v[2] == 99 && v[3] < 72 ) ) )
	{
	 {
 set_kb_item(name:"SMB/Missing/MS06-047", value:TRUE);
 hotfix_security_warning();
 }
	NetUseDel();
	exit(0);
	}
 }
 else 
 {
  NetUseDel();
  exit(1);
 }
}


NetUseDel();
