#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42117);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2009-0090", "CVE-2009-0091", "CVE-2009-2497");
  script_bugtraq_id(36611, 36617, 36618);
  script_xref(name:"OSVDB", value:"58849");
  script_xref(name:"OSVDB", value:"58850");
  script_xref(name:"OSVDB", value:"58851");

  script_name(english:string( "MS09-061: Vulnerabilities in the Microsoft .NET Common Language Runtime Could Allow Remote Code Execution (974378)" ) );
  script_summary(english:"Checks version of mscorlib.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The Microsoft .NET Common Language Runtime is affected by multiple\n",
      "vulnerabilities."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The remote Windows host is running a version of the Microsoft .NET\n",
      "Framework that is affected by multiple vulnerabilities :\n",
      "\n",
      "  - A remote code execution vulnerability exists in the\n",
      "    Microsoft .NET Framework that could allow a malicious\n",
      "    Microsoft .NET application to obtain a managed pointer\n",
      "    pointer to stack memory that is no longer used. The\n",
      "    malicious Microsoft .NET application could then\n",
      "    use this pointer to modify legitimate values placed at\n",
      "    that stack location later, eading to arbitrary\n",
      "    unmanaged code execution. Microsoft .NET applications \n",
      "    that are not malicious are not at risk for being\n",
      "    compromised because of this vulnerability.(CVE-2009-0090)\n",
      "\n",
      "  - A remote code execution vulnerability exists in the Microsoft\n",
      "    .NET Framework that could allow a malicious Microsoft .NET\n",
      "    application to bypass a type equality check. The malicious\n",
      "    Microsoft .NET  could exploit this vulnerability by casting\n",
      "    an object of one type into another type, leading to arbitrary\n",
      "    unmanaged code execution.  Microsoft .NET applications that \n",
      "    are not malicious are not at risk for being compromised because\n",
      "     of this vulnerability.(CVE-2009-0091)\n",
      "\n",
      "  - A remote code execution vulnerability exists in the Microsoft\n",
      "    .NET Framework that can allow a malicious Microsoft .NET\n",
      "    application or a malicious Silverlight application to modify\n",
      "    memory of the attacker's choice, leading to arbitrary unmanaged\n",
      "    code execution. Microsoft .NET applications and Silverlight\n",
      "    applications that are not malicious are not at risk for being\n",
      "    compromised because of this vulnerability.(CVE-2009-2497)"
    )
  );
  script_set_attribute(
    attribute:"solution",
    value:string(
      "Microsoft has released a set of patches for .NET Framework 1.1, 2.0\n",
      "and 3.5 :\n",
      "\n",
      "http://www.microsoft.com/technet/security/bulletin/MS09-061.mspx"
    )
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/10/13"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/10/13"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/10/14"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "silverlight_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");

rootfile = hotfix_get_systemroot();
if(!rootfile)
  exit(1, "Can't get system root." );

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
dotNET11 = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft.Net\Framework\v1.1.4322\mscorlib.dll", string:rootfile);
dotNET20 = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft.Net\Framework\v2.0.50727\mscorlib.dll", string:rootfile);

name 	  =  kb_smb_name();
login	  =  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();

if(!get_port_state(port))
  exit(1, "Port "+port+" is not open." );

soc = open_sock_tcp(port);
if(!soc)
  exit(1, "Can't open socket on port "+port+"." );

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 )
  exit(1, "Can't connect to '"+share+"' share." );

report = '';
handle = CreateFile(  file:dotNET11,
                      desired_access:GENERIC_READ,
                      file_attributes:FILE_ATTRIBUTE_NORMAL,
                      share_mode:FILE_SHARE_READ,
                      create_disposition:OPEN_EXISTING );
if( ! isnull(handle) )
{
  v = GetFileVersion(handle:handle);
  CloseFile(handle:handle);
  if ( !isnull( v ) )
  {
    if ( v[0] == 1 && v[1] == 1 && v[2] == 4322 && v[3] < 2443 )
    {
      report = string( report,
      '  Product           : Microsoft .NET Framework 1.1\n',
      '  Path              : ', dotNET11, '\n',
      '  Installed version : 1.1.4322.', v[3], '\n',
      '  Fix               : 1.1.4322.2443\n' );
    }
  }
}

handle = CreateFile(  file:dotNET20,
                      desired_access:GENERIC_READ,
                      file_attributes:FILE_ATTRIBUTE_NORMAL,
                      share_mode:FILE_SHARE_READ,
                      create_disposition:OPEN_EXISTING );
if( ! isnull(handle) )
{
  v = GetFileVersion(handle:handle);
  CloseFile(handle:handle);
  if ( !isnull( v ) )
  {
    if ( v[0] == 2 && v[1] == 0 && v[2] == 50727 )
    {
      if ( report ) report = string( report, '\n' );

      if (
        hotfix_check_sp(vista:1) > 0 &&
        v[3] > 0 && v[3] < 1003
      )
      {
        # .NET 2.0 SP0 is only affected on Vista SP0
        report = string( report,
          '  Product           : Microsoft .NET Framework 2.0\n',
          '  Path              : ', dotNET20, '\n',
          '  Installed version : 2.0.50727.', v[3], '\n',
          '  Fix               : 2.0.50727.1003\n' );
      }
      else if (
        hotfix_check_sp(win2k:6, xp:4, win2003:3, vista:2) > 0 &&
        v[3] > 1500 && v[3] < 1873  
      )
      {
        # .NET 2.0 SP1 affected on all win2k, xp, 2k3, and vista/2k8 before SP2
        report = string( report,
          '  Product           : Microsoft .NET Framework 2.0 SP1\n',
          '  Path              : ', dotNET20, '\n',
          '  Installed version : 2.0.50727.', v[3], '\n',
          '  Fix               : 2.0.50727.1873\n'  );
      }
      else if ( v[3] > 3000 && v[3] < 3603  )
      {
        report = string( report,
          '  Product           : Microsoft .NET Framework 2.0 SP2\n',   # XP to Vista SP1
          '  Path              : ', dotNET20, '\n',
          '  Installed version : 2.0.50727.', v[3], '\n',
          '  Fix               : 2.0.50727.3603\n'  );
      }
      else if ( v[3] > 4000 && v[3] < 4200  )
      {
        report = string( report,
          '  Product           : Microsoft .NET Framework 2.0 SP2\n',   # Vista SP2
          '  Path              : ', dotNET20, '\n',
          '  Installed version : 2.0.50727.', v[3], '\n',
          '  Fix               : 2.0.50727.4200\n'  );
      }
      else if (
        hotfix_check_sp(win7:1) > 0 &&
        v[3] > 4800 && v[3] < 4927
      )
      {
        # .NET 3.5.1 only affected on win7 and 2k8 r2
        report = string( report,
          '  Product           : Microsoft .NET Framework 3.5.1\n',
          '  Path              : ', dotNET20, '\n',
          '  Installed version : 2.0.50727.', v[3], '\n',
          '  Fix               : 2.0.50727.4927\n'  );
      }
    }
  }
}

NetUseDel();

ver = get_kb_item( "SMB/Silverlight/Version" );
if ( !isnull( ver ) )
{
  v = split( ver, sep:'.', keep:FALSE );
  if ( int( v[0] ) < 3  )
  {
    if ( report ) report = string( report, '\n' );
    path = get_kb_item( "SMB/Silverlight/Path" );
    report = string( report,
    '  Product           : Microsoft Silverlight\n',
    '  Path              : ', path, '\n',
    '  Installed version : ', ver, '\n',
    '  Fix               : 3.0.40818.0\n' );
  }
}

if ( report )
{
  set_kb_item(name:"SMB/Missing/MS09-061", value:TRUE);
  security_hole(port:port, extra:report);
}
else
  exit( 0, 'The host is not affected.' );
