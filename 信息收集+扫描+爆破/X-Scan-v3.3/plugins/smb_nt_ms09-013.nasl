#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(36151);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-0086", "CVE-2009-0089", "CVE-2009-0550");
  script_bugtraq_id(34435, 34437, 34439);
  script_xref(name:"OSVDB", value:"53619");
  script_xref(name:"OSVDB", value:"53620");
  script_xref(name:"OSVDB", value:"53621");

  script_name(english: "MS09-013: Vulnerabilities in Windows HTTP Services Could Allow Remote Code Execution (960803)");
  script_summary(english:"Checks version of Winhttp.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote host contains an API that is affected by multiple\n",
      "vulnerabilities."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The version of Windows HTTP Services installed on the remote host is\n",
      "affected by several vulnerabilities :\n",
      "\n",
      "  - An integer underflow triggered by a specially crafted \n",
      "    response from a malicious web server (for example, \n",
      "    during device discovery of UPnP devices on a network)\n",
      "    may allow for arbitrary code execution. (CVE-2009-0086)\n",
      "\n",
      "  - Incomplete validation of the distinguished name in a\n",
      "    digital certificate may, in combination with other\n",
      "    attacks, allow an attacker to successfully spoof the\n",
      "    digital certificate of a third-party web site. \n",
      "    (CVE-2009-0089)\n",
      "\n",
      "  - A flaw in the way that Windows HTTP Services handles\n",
      "    NTLM credentials may allow an attacker to reflect back\n",
      "    a user's credentials and thereby gain access as that \n",
      "    user. (CVE-2009-0550)"
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Microsoft has released a set of patches for Windows 2000, XP, 2003,\n",
      "Vista and 2008 :\n",
      "\n",
      "http://www.microsoft.com/technet/security/Bulletin/MS09-013.mspx"
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");


if (hotfix_check_sp(win2k:6, xp:4, win2003:3, vista:2) <= 0) exit(0);

if (is_accessible_share())
{
  if (
    # Windows Vista and Windows Server 2008
    hotfix_is_vulnerable(os:"6.0", sp:1, file:"Winhttp.dll", version:"6.0.6001.22323", min_version:"6.0.6001.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:1, file:"Winhttp.dll", version:"6.0.6001.18178", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:0, file:"Winhttp.dll", version:"6.0.6000.20971", min_version:"6.0.6000.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:0, file:"Winhttp.dll", version:"6.0.6000.16786", dir:"\system32") ||


    # Windows XP
    hotfix_is_vulnerable(os:"5.1", sp:3, file:"Winhttp.dll", version:"5.1.2600.5727", dir:"\System32") ||
    hotfix_is_vulnerable(os:"5.1", sp:2, file:"Winhttp.dll", version:"5.1.2600.3494", dir:"\System32") ||

    # Windows 2000
    hotfix_is_vulnerable(os:"5.0", file:"Winhttp.dll", version:"5.1.2600.3490", dir:"\System32")
  ) {
 set_kb_item(name:"SMB/Missing/MS09-013", value:TRUE);
 hotfix_security_hole();
 }
 
  hotfix_check_fversion_end(); 

 if ( hotfix_check_sp(win2003:3) > 0 )
 {
  patched =  0;
  rootfile = hotfix_get_systemroot();
  if ( ! rootfile ) exit(1);


  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
  path = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:rootfile);

  name    =  kb_smb_name();
  login   =  kb_smb_login();
  pass    =  kb_smb_password();
  domain  =  kb_smb_domain();
  port    =  kb_smb_transport();

  if(!get_port_state(port))exit(1);

  soc = open_sock_tcp(port);
  if(!soc)exit(1);

  session_init(socket:soc, hostname:name);
  r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if ( r != 1 ) exit(1);

  paths = make_list (
      "\WinSxS\amd64_Microsoft.Windows.WinHTTP_6595b64144ccf1df_5.1.3790.4427_x-ww_2FBA28DC",
      "\WinSxS\x86_Microsoft.Windows.WinHTTP_6595b64144ccf1df_5.1.3790.4427_x-ww_FDB042FC",
      "\WinSXS\amd64_Microsoft.Windows.WinHTTP_6595b64144ccf1df_5.1.3790.3262_x-ww_003B3A12",
      "\WinSxS\x86_Microsoft.Windows.WinHTTP_6595b64144ccf1df_5.1.3790.3262_x-ww_CE315432"
      );
  
  foreach spath (paths)
 {
  spath = path + spath;
  handle =  CreateFile (file:spath, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_DIRECTORY, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
  if ( ! isnull(handle) )
  {
   patched++;
   CloseFile(handle:handle);
    
   break;
  }
 }

 NetUseDel();
 if ( ! patched ) {
 set_kb_item(name:"SMB/Missing/MS09-013", value:TRUE);
 hotfix_security_hole();
 }
 }
}
