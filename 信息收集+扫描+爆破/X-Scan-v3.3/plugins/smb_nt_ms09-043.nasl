#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(40562);
 script_version("$Revision: 1.3 $");

 script_cve_id("CVE-2009-0562", "CVE-2009-2496", "CVE-2009-1136", "CVE-2009-1534");
 script_bugtraq_id(35642, 35990, 35991, 35992);
 script_xref(name:"OSVDB", value:"55806");
 script_xref(name:"OSVDB", value:"56914");
 script_xref(name:"OSVDB", value:"56915");
 script_xref(name:"OSVDB", value:"56916");
 script_xref(name:"Secunia", value:"35800");

 script_name(english:"MS09-043: Vulnerabilities in Microsoft Office Web Components Could Allow Remote Code Execution (957638)");
 script_summary(english:"Determines the version of MSO.dll");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Office Web Components." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Office Web
Components that is affected by various flaws that may allow arbitrary
code to be run. 

To succeed, the attacker would have to send specially crafted URLs to
a user of the remote computer and have him process it with Microsoft
Office Web Components." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office XP and 2003, as 
well as for Microsoft ISA server :

http://www.microsoft.com/technet/security/bulletin/ms09-043.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

 script_set_attribute(
  attribute:"patch_publication_date", 
  value:"2009/08/11"
 );
 script_set_attribute(
  attribute:"plugin_publication_date", 
  value:"2009/08/11"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows : Microsoft Bulletins");

 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_activex_func.inc");

if ( ! get_kb_item("SMB/WindowsVersion") ) exit(1);
path = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc");
if ( path )
{
  # This is MS ISA

 if (activex_init() != ACX_OK) exit(1, "Could not initialize the ActiveX checks");

 # Test each control.
 info = "";
 clsids = make_list(
  "{0002E543-0000-0000-C000-000000000046}",
  "{0002E55B-0000-0000-C000-000000000046}"
 );

foreach clsid (clsids)
{
  file = activex_get_filename(clsid:clsid);
  if (file)
  {
    if (activex_get_killbit(clsid:clsid) != TRUE)
    {
      version = activex_get_fileversion(clsid:clsid);
      if (!version) version = "Unknown";

      info += string(
        "\n",
        "  Class Identifier : ", clsid, "\n",
        "  Filename         : ", file, "\n",
        "  Version          : ", version, "\n"
      );
      if (!thorough_tests) break;
    }
  }
}
 activex_end();
 exit(0, "Host is patched");
}


office_version = hotfix_check_office_version ();
if ( !office_version ) exit(0, "Office is not installed on the remote host");

rootfile = hotfix_get_officeprogramfilesdir();
if ( ! rootfile ) exit(1, "Could not find the install location of MS Office");


if ( "9.0" >< office_version )
	{
	dll  =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft Office\Office\msowc.dll", string:rootfile);
	}
else if ( "10.0" >< office_version )
	dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft Office\Office10\owc10.dll", string:rootfile);
else if ( "12.0" >< office_version )
	{
	rootfile = hotfix_get_officecommonfilesdir();
	dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft Shared\Web Components", string:rootfile);
	dll += "\11\Owc11.dll";
	}

else exit(0, "Office version is not  affected");


share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);

name 	=  kb_smb_name();
login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();

if(!get_port_state(port))exit(1, "Could not connect to the SMB port of the remote host");

soc = open_sock_tcp(port);
if(!soc)exit(1, "Could not connect to the SMB port of the remote host");


session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 ) exit(1, "Could not log into the remote host");


handle =  CreateFile (file:dll, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

if ( ! isnull(handle) )
{
 v = GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if ( !isnull(v) ) 
  {
  	 if ( ( v[0] == 9 &&  v[1] == 0 && v[2] == 0 && v[3] < 8977) ||
	      ( v[0] == 10 && v[1] == 0 && v[2] < 6854 )  ||
	      ( v[0] == 12 && v[1] == 0 && ( v[2] < 6502 || ( v[2] == 6502 && v[3] < 5000 ) ) ) )
	 {
  set_kb_item(name:"SMB/Missing/MS09-043", value:TRUE);
  hotfix_security_hole();
  NetUseDel();
  exit(0);
   }
  }
}

NetUseDel();
exit(0, "Host is patched.");
