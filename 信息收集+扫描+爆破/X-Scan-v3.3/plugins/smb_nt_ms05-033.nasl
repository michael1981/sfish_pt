#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(18486);
 script_version("$Revision: 1.13 $");

 script_cve_id("CVE-2005-0488", "CVE-2005-1205");
 script_bugtraq_id(13940);
 script_xref(name:"OSVDB", value:"17303");

 name["english"] = "MS05-033: Vulnerability in Telnet Client Could Allow Information Disclosure (896428)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to disclose user information." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a flaw the Telnet client that
may allow an attacker to read the session variables of users
connecting to a rogue telnet server." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-033.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 896428";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
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


if ( hotfix_check_sp(xp:3, win2003:2) > 0 ) 
{
 if (is_accessible_share())
 {
  if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"telnet.exe", version:"5.2.3790.329", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.2", sp:1, file:"telnet.exe", version:"5.2.3790.2442", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.1", sp:1, file:"telnet.exe", version:"5.1.2600.1684", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.1", sp:2, file:"telnet.exe", version:"5.1.2600.2674", dir:"\system32") )
 {
 set_kb_item(name:"SMB/Missing/MS05-033", value:TRUE);
 security_warning(get_kb_item("SMB/transport"));
 }
 
  hotfix_check_fversion_end(); 
  exit (0);
 }
}

if ( hotfix_check_sp(win2k:6) > 0  && hotfix_missing(name:"896428") > 0 ) 
{
 name	= kb_smb_name(); 	
 login	= kb_smb_login(); 
 pass	= kb_smb_password(); 	
 domain  = kb_smb_domain(); 	
 port	= kb_smb_transport();

 if ( ! get_port_state(port) ) exit(0);
 soc = open_sock_tcp(port);
 if ( ! soc ) exit(0);

 session_init(socket:soc, hostname:name);
 r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
 if ( r != 1 ) exit(0);

 hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
 if ( isnull(hklm) ) 
 {
  NetUseDel();
  exit(0);
 }

 key = "SOFTWARE\Microsoft\Services for Unix";
 item = "InstallPath";
 key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
 if ( ! isnull(key_h) )
  value = RegQueryValue(handle:key_h, item:item);
 
 RegCloseKey (handle:hklm);
 NetUseDel();

 if ( !isnull(value) ) {
 set_kb_item(name:"SMB/Missing/MS05-033", value:TRUE);
 hotfix_security_warning();
 }
}
