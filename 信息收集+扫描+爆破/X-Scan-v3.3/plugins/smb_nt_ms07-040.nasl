#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(25691);
 script_version("$Revision: 1.8 $");

 script_cve_id(
  "CVE-2006-7192", 
  "CVE-2007-0041", 
  "CVE-2007-0042", 
  "CVE-2007-0043"
 );
 script_bugtraq_id(20753, 24778, 24791, 24811);
 script_xref(name:"OSVDB", value:"35269");
 script_xref(name:"OSVDB", value:"35954");
 script_xref(name:"OSVDB", value:"35955");
 script_xref(name:"OSVDB", value:"35956");

 name["english"] = "MS07-040: Vulnerabilities in .NET Framework Could Allow Remote Code Execution (931212)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote .Net Framework is vulnerable to code execution attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the ASP.NET framework that
contains multiple vulnerabilities :

  - A PE Loader vulnerability could allow an attacker to 
    execute arbitrary code with the privilege of the 
    logged-on user.

  - An ASP.NET NULL byte termination vulnerability could 
    allow an attacker to retrieve the content of the web 
    server.

  - A JIT compiler vulnerability could allow an attacker to 
    execute arbitrary code with the privilege of the 
    logged-on user." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for .NET Framework 1.0, 1.1
and 2.0 :

http://www.microsoft.com/technet/security/bulletin/ms07-040.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines the version of the ASP.Net DLLs";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
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
dll10 = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft.Net\Framework\v1.1.4322\System.web.dll", string:rootfile);
dll11 = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft.Net\Framework\v1.0.3705\System.web.dll", string:rootfile);
dll20 = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft.Net\Framework\v2.0.50727\System.web.dll", string:rootfile);

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


handle =  CreateFile (file:dll20, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING); 

if ( isnull(handle) )
{
 handle = CreateFile (file:dll11, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING); 

 if ( isnull(handle) )
   handle = CreateFile (file:dll10, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING); 
}

	
if( ! isnull(handle) )
{
 v = GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if ( ! isnull(v) ) 
 {
  if ( (v[0] == 1 && v[1] == 0 && v[2] < 3705) ||
       (v[0] == 1 && v[1] == 0 && v[2] == 3705 && v[3] < 6060)  || # 1.0SP3
       
       (v[0] == 1 && v[1] == 1 && v[2] < 4322) ||
       (v[0] == 1 && v[1] == 1 && v[2] == 4322 && v[3] < 2407) ||  # 1.1 SP1

       (v[0] == 2 && v[1] == 0 && v[2] < 50727 ) ||
       (v[0] == 2 && v[1] == 0 && v[2] == 50727 && v[3] < 832 ) )
 {
 set_kb_item(name:"SMB/Missing/MS07-040", value:TRUE);
 hotfix_security_hole();
 }
 }
}

NetUseDel();

