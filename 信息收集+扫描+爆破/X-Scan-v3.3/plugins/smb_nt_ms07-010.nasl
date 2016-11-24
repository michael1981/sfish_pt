#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(24334);
 script_cve_id("CVE-2006-5270");
 script_bugtraq_id(22479);
 script_xref(name:"OSVDB", value:"31888");
 script_version("$Revision: 1.9 $");

 name["english"] = "MS07-010: Vulnerability in Microsoft Malware Protection Engine Could Allow Remote Code Execution (932135)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the AntiMalware program." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows Malware Protection engine which
is vulnerable to a bug in the PDF file handling routine which may allow an 
attacker execute arbitrary code on the remote host by sending a specially crafted 
file." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Defender and Live OneCare:

http://www.microsoft.com/technet/security/bulletin/ms07-010.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );



script_end_attributes();

 
 summary["english"] = "Determines the version of Malware Protection Engine";

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


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();

if (!get_port_state(port))
  exit(1);

soc = open_sock_tcp(port);
if (!soc)
  exit(1);

session_init(socket:soc, hostname:kb_smb_name());
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (r != 1) 
  exit(1);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
 NetUseDel();
 exit(1);
}

keys = make_list (
	"SOFTWARE\Microsoft\Windows Defender\Signature Updates",
	"SOFTWARE\Microsoft\OneCare Protection\Signature Updates"
	);

foreach key (keys)
{
 value = NULL;
 item = "EngineVersion";
 key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
 if (!isnull(key_h))
 {
  value = RegQueryValue(handle:key_h, item:item);
  RegCloseKey(handle:key_h);
 }

 if (!isnull(value))
 {
  v = split(value[1], sep:".", keep:FALSE); 

  if ( ( (int(v[0]) == 1) && (int(v[1]) < 1) ) ||
       ( (int(v[0]) == 1) && (int(v[1]) == 1) && (int(v[2]) < 2101) ) )
  {
 {
 set_kb_item(name:"SMB/Missing/MS07-010", value:TRUE);
 hotfix_security_hole();
 }
   break;
  }
 }
}


RegCloseKey(handle:hklm);
NetUseDel();
