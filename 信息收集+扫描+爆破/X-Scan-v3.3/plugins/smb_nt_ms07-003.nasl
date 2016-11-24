#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(23999);
 script_cve_id("CVE-2006-1305", "CVE-2007-0033", "CVE-2007-0034");
 script_bugtraq_id(21931, 21936, 21937);
 script_xref(name:"OSVDB", value:"31252");
 script_xref(name:"OSVDB", value:"31253");
 script_xref(name:"OSVDB", value:"31254");
 script_version("$Revision: 1.11 $");

 name["english"] = "MS07-003: Vulnerabilities in Microsoft Outlook Could Allow Remote Code Execution (925938)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the email client." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of outlook or exchange which is vulnerable
to a bug in the VEVENT record handling routine which may allow an attacker execute
arbitrary code on the remote host by sending a specially crafted email." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Outlook 2000, 2002 and 2003

http://www.microsoft.com/technet/security/bulletin/ms07-003.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );



script_end_attributes();

 
 summary["english"] = "Determines the version of OutLook";

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


version = hotfix_check_outlook_version();
if (version)
{
 CommonFilesDir = hotfix_get_officecommonfilesdir();
 if (CommonFilesDir )
 {
  login	=  kb_smb_login();
  pass  	=  kb_smb_password();
  domain 	=  kb_smb_domain();
  port    =  kb_smb_transport();
  if (!get_port_state(port))exit(1);

  soc = open_sock_tcp(port);
  if(!soc)exit(1);

  session_init(socket:soc, hostname:kb_smb_name());
  r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
  if ( r != 1 ) exit(1);

  hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
  if ( isnull(hklm) )
  {
   NetUseDel();
   exit(1);
  }

  value = NULL;
  key_h = RegOpenKey(handle:hklm, key:"SOFTWARE\Microsoft\Office\" + version + "\Outlook\InstallRoot", mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
   value = RegQueryValue(handle:key_h, item:"Path");
   RegCloseKey(handle:key_h);
  }

  RegCloseKey(handle:hklm);
  NetUseDel();

  if (!isnull(value))
  {
   if (version == "9.0")
   {
    if ( hotfix_check_fversion(path:value[1], file:"Outllib.dll", version:"9.0.0.8954") == HCF_OLDER ) {
 set_kb_item(name:"SMB/Missing/MS07-003", value:TRUE);
 hotfix_security_hole();
 }
   }
   else if (version == "10.0")
   {
    if ( hotfix_check_fversion(path:value[1], file:"Outllibr.dll", version:"10.0.6822.0") == HCF_OLDER ) {
 set_kb_item(name:"SMB/Missing/MS07-003", value:TRUE);
 hotfix_security_hole();
 }
   }
   else if (version == "11.0")
   {
    if ( hotfix_check_fversion(path:value[1], file:"Outllib.dll", version:"11.0.8118.0") == HCF_OLDER ) {
 set_kb_item(name:"SMB/Missing/MS07-003", value:TRUE);
 hotfix_security_hole();
 }
   }
  }
 }
}


