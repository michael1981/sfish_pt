#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(25901);
 script_version("$Revision: 1.7 $");

 script_cve_id("CVE-2007-3032", "CVE-2007-3033", "CVE-2007-3891");
 script_bugtraq_id(25287, 25304, 25306);
 script_xref(name:"OSVDB", value:"36391");
 script_xref(name:"OSVDB", value:"36392");
 script_xref(name:"OSVDB", value:"36393");
 
 name["english"] = "MS07-048: Vulnerabilities in Windows Gadgets Could Allow Remote Code Execution (938123)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Desktop
Gadgets." );
 script_set_attribute(attribute:"description", value:
"The remote version of Microsoft Windows is missing a critical security
update that fixes several vulnerabilities in the Desktop Gadgets. 

An attacker may exploit these flaws to execute arbitrary code on the
remote host.  To exploit this flaw, an attacker would need to lure the
user into adding a malicious RSS feed or mail contact or using a
malicious weather link." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista :

http://www.microsoft.com/technet/security/bulletin/ms07-048.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 938123";
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

if ( hotfix_check_sp(vista:1) <= 0 ) exit(0);


name 	=  kb_smb_name();
login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();

if(!get_port_state(port))exit(1);

soc = open_sock_tcp(port);
if(!soc)exit(1);

path = hotfix_get_programfilesdir();
if (!path)
  exit (1);


dir =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Windows Sidebar\Gadgets\RSSFeeds.Gadget", string:path);
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 ) exit(1);

retx  = FindFirstFile(pattern:dir + "\??-??");
if (isnull(retx) || strlen(retx[1]) != 5)
{
 NetUseDel();
 exit(0);
}

xml = dir + "\" + retx[1] + "\gadget.xml";

handle =  CreateFile (file:xml, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

if ( ! isnull(handle) )
{
 data = ReadFile(handle:handle, offset:0, length:4096);
 CloseFile(handle:handle);

 if (egrep(pattern:'<version><!--_locComment_text="{Locked}"-->[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+</version>', string:data))
 {
  version = ereg_replace(pattern:'.*<version><!--_locComment_text="{Locked}"-->([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)</version>.*', string:data, replace:"\1");
  v = split(version, sep:".", keep:FALSE);

  if ( !isnull(v) ) 
    if ( int(v[0]) == 1 &&  int(v[1]) < 1 ) {
 set_kb_item(name:"SMB/Missing/MS07-048", value:TRUE);
 hotfix_security_warning();
 }
 }
}

NetUseDel();
