#
# (C) Tenable Network Security, Inc.
#
include("compat.inc");

if(description)
{
 script_id(25167);
 script_version("$Revision: 1.12 $");

 script_cve_id("CVE-2007-0940");
 script_bugtraq_id(23782);
 script_xref(name:"OSVDB", value:"34397");

 name["english"] = "MS07-028: Vulnerability in CAPICOM Could Allow Remote Code Execution (931906)";


 script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
browser." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the CAPICOM library
(Cryptographic API Component Object Model) which is subject to a flaw
which may allow arbitrary code to be run.

An attacker may use this to execute arbitrary code on this host.

To exploit this flaw, an attacker would need to set up a rogue web
site and lure a victim on the remote host into visiting it." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for CAPICOM :

http://www.microsoft.com/technet/security/bulletin/ms07-028.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );


script_end_attributes();


 summary["english"] = "Determines the version of CAPICOM.dll";

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

if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);
name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if (!get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);

session_init(socket:soc, hostname:name);
rc = NetUseAdd(login:login, password:pass, domain:domain);
if (rc != 1)
{
  NetUseDel();
  exit( 1, 'Could not login with supplied credentials' );
}


# Determine where it's installed.
keys = make_list(
	"SOFTWARE\\Classes\\CAPICOM.Certificates\\CLSID",
	"SOFTWARE\\Classes\\CAPICOM.Certificates.1\\CLSID",
	"SOFTWARE\\Classes\\CAPICOM.Certificates.2\\CLSID",
	"SOFTWARE\\Classes\\CAPICOM.Certificates.3\\CLSID"
	);

foreach key (keys)
{
 rc = NetUseAdd(share:"IPC$");
 if (rc != 1)
 {
  NetUseDel();
  exit( 1, 'Could not conenct to IPC$ share' );
 }

 # Connect to remote registry.
 hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
 if (isnull(hklm))
 {
   NetUseDel();
   exit( 1, 'Could not connect to registry' );
 }


 value = NULL;

 key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
 if (!isnull(key_h))
 {
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value))
  {
    value = value[1];
    RegCloseKey(handle:key_h);

    key_h = RegOpenKey(handle:hklm, key:'SOFTWARE\\Classes\\CLSID\\' + value + "\InprocServer32", mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h))
    {
      value = RegQueryValue(handle:key_h, item:NULL);
      if (!isnull(value))
        value = value[1];
    }
    else
       value = NULL;
    }
    RegCloseKey(handle:key_h);
  }

  RegCloseKey(handle:hklm);
  NetUseDel (close:FALSE);

  if (!isnull(value))
  {
    value = str_replace(string:value, find:'"', replace:"");

    share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:value);
    dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:value);

    r = NetUseAdd(share:share);
    if ( r != 1 )
    {
      NetUseDel();
      exit(1, 'Could not connect to ' + share + ' share' );
    }
    v = get_kb_item("SMB/FileVersions" + tolower(str_replace(string:dll, find:'\\', replace:"/")));
    if ( isnull(v) )
    {
      handle = CreateFile (file:dll, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

      if ( ! isnull(handle) )
      {
        v = GetFileVersion(handle:handle);
        CloseFile(handle:handle);
      }
    }
    else
    {
      v = split( v, sep:".", keep:FALSE );
      v = make_list( int( v[0] ), int( v[1] ), int( v[2] ), int( v[3] ) );
    }

    if ( !isnull(v) )
    {
      set_kb_item(name:"SMB/FileVersions" + tolower(str_replace(string:dll, find:'\\', replace:"/")), value:v[0] + "." + v[1] + "." + v[2] + "." + v[3]);
      if (  ( v[0] < 2)  ||
            ( v[0] == 2 && v[1] < 1 ) ||
            ( v[0] == 2 && v[1] == 1 && v[2] == 0 && v[3] < 2 ) )
      {
        version = string(v[0], ".", v[1], ".", v[2], ".", v[3]);
        report = string(  "Information about the vulnerable control :\n",
                          "\n",
                          "  Registry entry : HKLM\\", key, "\n",
                          "  File           : ", value, "\n",
                          "  Version        : ", version, "\n"
                        );
        hotfix_add_report(report);
        set_kb_item(name:"SMB/Missing/MS07-028", value:TRUE);
        hotfix_security_hole();
        exit( 0 );
      }
    }
  }
  NetUseDel(close:FALSE);
}
NetUseDel();
exit( 1, "Could not find version of capicom.dll" );
