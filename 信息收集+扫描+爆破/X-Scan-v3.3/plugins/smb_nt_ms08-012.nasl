#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(31046);
 script_version("$Revision: 1.7 $");

 script_cve_id("CVE-2008-0102", "CVE-2008-0104");
 script_bugtraq_id(27739, 27740);

 name["english"] = "MS08-012: Vulnerability in Microsoft Publisher Could Allow Remote Code Execution (947085)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Publisher." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Publisher
which is subject to a flaw which may allow arbitrary code to be run.

An attacker may use this to execute arbitrary code on this host.

To succeed, the attacker would have to send a rogue file to 
a user of the remote computer and have it open it. Then a bug in
the font parsing handler would result in code execution." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Publisher 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms08-012.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
 summary["english"] = "Determines the version of MSPUB.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_nt_ms02-031.nasl");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

port = kb_smb_transport();

#
# PowerPoint
#
v = get_kb_item("SMB/Office/Publisher/Version");
if ( v ) 
{
 if(ereg(pattern:"^9\..*", string:v))
 {
  # Publisher 2000 - fixed in 9.00.00.8931
  sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
  if(sub != v && int(sub) < 8931 ) { {
 set_kb_item(name:"SMB/Missing/MS08-012", value:TRUE);
 hotfix_security_hole();
 }exit(0);}
 }
 else if(ereg(pattern:"^10\..*", string:v))
 {
  # Publisher XP - fixed in 10.0.6840.0
   middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 6840) { {
 set_kb_item(name:"SMB/Missing/MS08-012", value:TRUE);
 hotfix_security_hole();
 }exit(0);}
 }
 else if(ereg(pattern:"^11\..*", string:v))
 {
  # Publisher 2003 - fixed in 11.0.8200.0
   middle =  ereg_replace(pattern:"^11\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 8200) { {
 set_kb_item(name:"SMB/Missing/MS08-012", value:TRUE);
 hotfix_security_hole();
 }exit(0);}
 }
}


office_version = hotfix_check_office_version ();
if ( !office_version ) exit(0);

rootfile = hotfix_get_officeprogramfilesdir();
if ( ! rootfile ) exit(1);


if ( "9.0" >< office_version)
	{
	dll  =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft Office\Office\Prtf9.dll", string:rootfile);
	}
else if ( "10.0" >< office_version )
	dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft Office\Office10\Ptxt9.dll", string:rootfile);
else if ( "11.0" >< office_version )
	dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft Office\Office11\Prtf9.dll", string:rootfile);

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
  	 if ( ( v[0] == 9 &&  v[1] == 0 && v[2] == 0 && v[3] < 8929 )  ||
	      ( v[0] == 10 && v[1] == 0 && v[2] < 6840 ) ||
	      ( v[0] == 11 && v[1] == 0 && v[2] < 8200 )) {
 set_kb_item(name:"SMB/Missing/MS08-012", value:TRUE);
 hotfix_security_hole();
 }
  }
}

NetUseDel();
