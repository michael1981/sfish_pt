#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(22529);
 script_version("$Revision: 1.10 $");

 script_cve_id("CVE-2006-3436");
 script_bugtraq_id(20337);
 script_xref(name:"OSVDB", value:"29431");

 name["english"] = "MS06-056: Vulnerabilities in ASP.NET could allow information disclosure (922770)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote .Net Framework is vulnerable to a cross site scripting
attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the ASP.NET framework that
contains a cross-site scripting vulnerability that could allow an
attacker to execute arbitrary code in the browser of the users
visiting the remote web site." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 
2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-056.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
 summary["english"] = "Determines the version of the ASP.Net DLLs";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
rootfile = hotfix_get_systemroot();
if(!rootfile) exit(0);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft.Net\Framework\v2.0.50727\Aspnet_wp.exe", string:rootfile);


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
	
if( ! isnull(handle) )
{
 v = GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if ( ! isnull(v) ) 
 {
       if ((v[0] == 2 && v[1] == 0 && v[2] < 50727 ) ||
      	   (v[0] == 2 && v[1] == 0 && v[2] == 50727 && v[3] < 210 ) )
	{
	 {
 set_kb_item(name:"SMB/Missing/MS06-056", value:TRUE);
 hotfix_security_warning();
 }
	  set_kb_item(name: 'www/0/XSS', value: TRUE);
	}
 }
}

NetUseDel();
