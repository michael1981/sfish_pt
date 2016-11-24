#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(20910);
 script_version("$Revision: 1.9 $");

 script_cve_id("CVE-2006-0004");
 script_bugtraq_id(16634);
 script_xref(name:"OSVDB", value:"23135");
 
 name["english"] = "MS06-010: Vulnerability in PowerPoint 2000 Could Allow Information Disclosure (889167)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote version of PowerPoint is vulnerable to an information
disclosure attack." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of PowerPoint that is vulnerable to
an information disclosure attack. 

Specifically, an attacker could send a malformed PowerPoint file to a
a victim on the remote host.  When the victim opens the file, the
attacker may be able to obtain access to the files in the Temporary
Internet Files Folder of the remote host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for PowerPoint :

http://www.microsoft.com/technet/security/bulletin/ms06-010.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N" );
script_end_attributes();

 
 summary["english"] = "Determines the version of PowerPnt.exe";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys( "SMB/WindowsVersion", "SMB/registry_access");

 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


rootfile = hotfix_get_officeprogramfilesdir();
if ( ! rootfile ) exit(1);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
ppt =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft Office\Office\PowerPnt.exe", string:rootfile);



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

handle =  CreateFile (file:ppt, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if ( ! isnull(handle) )
{
 ppt_version = v =  GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if ( ! isnull(v) ) 
 {
  set_kb_item(name:"SMB/Office/PowerPoint/Version", value:string(v[0], ".", v[1], ".", v[2], ".", v[3]));
 }
}


NetUseDel();

if ( ! isnull(ppt_version) ) 
{
 if ( ppt_version[0] == 9 && ppt_version[1] == 0 && ppt_version[2] == 0 && ppt_version[3] < 8936) 
	 {
 set_kb_item(name:"SMB/Missing/MS06-010", value:TRUE);
 hotfix_security_warning();
 }
}
