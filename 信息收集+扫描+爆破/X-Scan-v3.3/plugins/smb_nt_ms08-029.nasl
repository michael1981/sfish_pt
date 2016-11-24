#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(32313);
 script_version("$Revision: 1.5 $");

 script_cve_id("CVE-2008-1437","CVE-2008-1438");
 script_bugtraq_id(29060, 29073);
 script_xref(name:"OSVDB", value:"45027");
 script_xref(name:"OSVDB", value:"45028");

 name["english"] = "MS08-029: Vulnerabilities in Microsoft Malware Protection Engine Could Allow Denial of Service (952044)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to crash the AntiMalware program." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows Malware Protection
engine which is vulnerable to a bug in the file handling routine which
may allow an attacker to crash the protection engine." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Defender and Live
OneCare :

http://www.microsoft.com/technet/security/bulletin/ms08-029.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
 summary["english"] = "Determines the version of Malware Protection Engine";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
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
       ( (int(v[0]) == 1) && (int(v[1]) == 1) && (int(v[2]) < 3520) ) )
  {
 {
 set_kb_item(name:"SMB/Missing/MS08-029", value:TRUE);
 hotfix_security_warning();
 }
   break;
  }
 }
}


RegCloseKey(handle:hklm);
NetUseDel();
