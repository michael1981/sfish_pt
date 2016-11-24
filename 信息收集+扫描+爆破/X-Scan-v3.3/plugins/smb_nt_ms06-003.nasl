#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(20390);
 script_version("$Revision: 1.10 $");

 script_cve_id("CVE-2006-0002");
 script_bugtraq_id(16197);
 script_xref(name:"OSVDB", value:"22305");

 script_name(english:"MS06-003: Vulnerability in TNEF Decoding in Microsoft Outlook and Microsoft Exchange Could Allow Remote Code Execution (902412)");
 script_summary(english:"Determines the version of OutLook / Exchange");
  
 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "Arbitrary code can be executed on the remote host through the email\n",
   "client or server."
  )
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote host is running a version of Outlook or Exchange containing\n",
   "a bug in the Transport Neutral Encapsulation Format (TNEF) MIME\n",
   "attachment handling routine that may allow an attacker execute\n",
   "arbitrary code on the remote host by sending a specially crafted\n",
   "email."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Microsoft has released a set of patches for Office 2000, 2002, XP,\n",
   "2003, Exchange 5.0, 5.5 and 2000 :\n",
   "\n",
   "http://www.microsoft.com/technet/security/bulletin/ms06-003.mspx"
  )
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
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
 CommonFilesDir = hotfix_get_commonfilesdir();
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
    if ( hotfix_check_fversion(path:value[1], file:"Outex.dll", version:"8.30.3197.0") == HCF_OLDER ) {
 set_kb_item(name:"SMB/Missing/MS06-003", value:TRUE);
 hotfix_security_hole();
 }
   }
   else if (version == "10.0")
   {
    if ( hotfix_check_fversion(path:value[1], file:"Outllibr.dll", version:"10.0.6711.0") == HCF_OLDER ) {
 set_kb_item(name:"SMB/Missing/MS06-003", value:TRUE);
 hotfix_security_hole();
 }
   }
   else if (version == "11.0")
   {
    if ( hotfix_check_fversion(path:value[1], file:"Outllib.dll", version:"11.0.8002.0") == HCF_OLDER ) {
 set_kb_item(name:"SMB/Missing/MS06-003", value:TRUE);
 hotfix_security_hole();
 }
   }
  }
 }
}


version = get_kb_item ("SMB/Exchange/Version");
if ( !version ) exit (0);

if (version == 50)
{
 sp = get_kb_item ("SMB/Exchange/SP");
 rootfile = get_kb_item("SMB/Exchange/Path");
 if ( ! rootfile || ( sp && sp > 2) ) exit(0);
 rootfile = rootfile + "\bin";
 if ( hotfix_check_fversion(path:rootfile, file:"Mdbmsg.dll", version:"5.0.1462.22") == HCF_OLDER ) {
 set_kb_item(name:"SMB/Missing/MS06-003", value:TRUE);
 hotfix_security_hole();
 }

 hotfix_check_fversion_end();
}
else if (version == 55)
{
 sp = get_kb_item ("SMB/Exchange/SP");
 rootfile = get_kb_item("SMB/Exchange/Path");
 if ( ! rootfile || ( sp && sp > 4) ) exit(0);
 rootfile = rootfile + "\bin";
 if ( hotfix_check_fversion(path:rootfile, file:"Mdbmsg.dll", version:"5.5.2658.34") == HCF_OLDER ) {
 set_kb_item(name:"SMB/Missing/MS06-003", value:TRUE);
 hotfix_security_hole();
 }

 hotfix_check_fversion_end();
}
else if (version == 60)
{
 sp = get_kb_item ("SMB/Exchange/SP");
 rootfile = get_kb_item("SMB/Exchange/Path");
 if ( ! rootfile || ( sp && sp > 3) ) exit(0);
 rootfile = rootfile + "\bin";
 if ( hotfix_check_fversion(path:rootfile, file:"Mdbmsg.dll", version:"6.0.6617.47") == HCF_OLDER ) {
 set_kb_item(name:"SMB/Missing/MS06-003", value:TRUE);
 hotfix_security_hole();
 }

 hotfix_check_fversion_end();
}

