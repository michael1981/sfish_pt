#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11990);
 script_version("$Revision: 1.26 $");

 script_cve_id("CVE-2003-0903");
 script_bugtraq_id(9407);
 script_xref(name:"IAVA", value:"2004-B-0001");
 script_xref(name:"OSVDB", value:"3457");

 name["english"] = "MS04-003: MDAC Buffer Overflow (832483)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through MDAC server." );
 script_set_attribute(attribute:"description", value:
"The remote Microsoft Data Access Component (MDAC) server is vulnerable
to a flawthat could allow an attacker to execute arbitrary code on
this host, provided he can simulate responses from a SQL server. 

To exploit this flaw, an attacker would need to wait for a host
running a vulnerable MDAC implementation to send a broadcast query. 
He would then need to send a malicious packet pretending to come from
a SQL server." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 
2003 :

http://www.microsoft.com/technet/security/bulletin/ms04-003.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:A/AC:H/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Checks the version of MDAC";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( hotfix_check_sp(xp:2, win2k:5, win2003:1) <= 0 ) exit(0);


if ( ( version =  hotfix_data_access_version()) == NULL ) exit(0);
if(ereg(pattern:"^2\.6[3-9].*", string:version))exit(0); # SP3 applied


if ( ! get_kb_item("SMB/WindowsVersion") ) exit(1);

rootfile = hotfix_get_systemroot();
if ( ! rootfile ) exit(1);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\system32\odbcbcp.dll", string:rootfile);


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
 flag = 0;
 v = GetFileVersion(handle:handle);
 if (!isnull(v))
   set_kb_item (name:"SMB/MDAC_odbcbcp", value:string(v[0],".",v[1],".",v[2],".",v[3]));

 CloseFile(handle:handle);

 if ( v[0] == 3 )
	{
	 if ( (v[0] == 3 && v[1] < 70) || 
	      (v[0] == 3 && v[1] == 70 && v[2] < 11) ||
	      (v[0] == 3 && v[1] == 70 && v[2] == 11 && v[3] < 46 ) ) { {
 set_kb_item(name:"SMB/Missing/MS04-003", value:TRUE);
 hotfix_security_warning();
 }}
	}
 else if ( v[0] == 2000 )
	{
	 if ( ( v[0] == 2000 && v[1] == 80 && v[2] < 747) ||
	      ( v[0] == 2000 && v[1] == 80 && v[2] == 747 && v[3] < 0 ) ) { {
 set_kb_item(name:"SMB/Missing/MS04-003", value:TRUE);
 hotfix_security_warning();
 }}

	 if ( ( v[0] == 2000 && v[1] == 81 && v[2] < 9002) ||
	      ( v[0] == 2000 && v[1] == 81 && v[2] == 9002 && v[3] < 0 ) ) { {
 set_kb_item(name:"SMB/Missing/MS04-003", value:TRUE);
 hotfix_security_warning();
 }}

	 if ( ( v[0] == 2000 && v[1] == 81 && v[2] >= 9030 && v[2] < 9042) ) { {
 set_kb_item(name:"SMB/Missing/MS04-003", value:TRUE);
 hotfix_security_warning();
 }}

	 if ( ( v[0] == 2000 && v[1] == 85 && v[2] < 1025) ||
	      ( v[0] == 2000 && v[1] == 85 && v[2] == 1025 && v[3] < 0 ) ) { {
 set_kb_item(name:"SMB/Missing/MS04-003", value:TRUE);
 hotfix_security_warning();
 }}
	}
}

NetUseDel();

