#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if (description)
{
  script_id(42118);
  script_version("$Revision: 1.6 $");

  script_cve_id(
    "CVE-2009-2500",
    "CVE-2009-2501",
    "CVE-2009-2502",
    "CVE-2009-2503",
    "CVE-2009-2504",
    "CVE-2009-2518",
    "CVE-2009-2528",
    "CVE-2009-3126"
  );
  script_bugtraq_id(36619, 36645, 36646, 36647, 36648, 36649, 36650, 36651);
  script_xref(name:"OSVDB", value:"58863");
  script_xref(name:"OSVDB", value:"58864");
  script_xref(name:"OSVDB", value:"58865");
  script_xref(name:"OSVDB", value:"58866");
  script_xref(name:"OSVDB", value:"58867");
  script_xref(name:"OSVDB", value:"58868");
  script_xref(name:"OSVDB", value:"58869");
  script_xref(name:"OSVDB", value:"58870");

  script_name(english:"MS09-062: Vulnerabilities in GDI+ Could Allow Remote Code Execution (957488)");
  script_summary(english:"Checks the version of gdiplus.exe");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "Arbitrary code can be executed on the remote host through the\n",
      "Microsoft GDI rendering engine."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The remote host is running a version of Windows that is affected by\n",
      "multiple buffer overflow vulnerabilities when viewing TIFF, PNG, BMP,\n",
      "and Office files, which may allow an attacker to execute arbitrary\n",
      "code on the remote host.  Additionally, there is a GDI+ .NET API\n",
      "vulnerability that allows a malicious .NET application to gain\n",
      "unmanaged code execution privileges.\n\n",
      "To exploit these flaws, an attacker would need to send a malformed\n",
      "image file to a user on the remote host and wait for them to open it\n",
      "using an affected Microsoft application."
    )
  );
  script_set_attribute(
    attribute:"solution",
    value:string(
      "Microsoft has released a set of patches for Windows XP, 2003, Vista,\n",
      "2008, IE, .NET Framework, Office, SQL Server, Developer Tools, and\n",
      "Forefront :\n",
      "\n",
      "http://www.microsoft.com/technet/security/Bulletin/MS09-062.mspx"
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
    value:"2009/10/15"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "mssql_version.nasl", "office_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


if (!get_kb_item("SMB/WindowsVersion")) exit(1, "The 'SMB/WindowsVersion' KB item is missing.");

MAX_RECURSE = 1;

rootfile = hotfix_get_systemroot();
if ( ! rootfile ) exit(1, "Can't get system root");

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
path = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:rootfile);

name    =  kb_smb_name();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();
port    =  kb_smb_transport();

if(!get_port_state(port))exit(1, "Port "+port+" is not open.");
soc = open_sock_tcp(port);
if(!soc)exit(1, "Can't open socket on port "+port+".");

session_init(socket:soc, hostname:name);
hcf_init = TRUE;


function list_dir(basedir, level, dir_pat, file_pat)
{
  local_var contents, ret, subdirs, subsub;

  # nb: limit how deep we'll recurse.
  if (level > MAX_RECURSE) return NULL;

  subdirs = NULL;
  if (isnull(dir_pat)) dir_pat = "";
  ret = FindFirstFile(pattern:basedir + "\*" + dir_pat + "*");

  contents = make_list();
  while (!isnull(ret[1]))
  {
    if (file_pat && ereg(pattern:file_pat, string:ret[1], icase:TRUE))
      contents = make_list(contents, basedir+"\"+ret[1]);

    subsub = NULL;
    if ("." != ret[1] && ".." != ret[1] && level <= MAX_RECURSE)
      subsub  = list_dir(basedir:basedir+"\"+ret[1], level:level+1, file_pat:file_pat);
    if (!isnull(subsub))
    {
      if (isnull(subdirs)) subdirs = make_list(subsub);
      else subdirs = make_list(subdirs, subsub);
    }
    ret = FindNextFile(handle:ret);
  }

  if (isnull(subdirs)) return contents;
  else return make_list(contents, subdirs);
}


# Returns the file version as a string, either from the KB or by
# calling GetFileVersion(). Assumes we're already connected to the
# correct share.
function get_file_version()
{
  local_var fh, file, ver, version;

  if (isnull(_FCT_ANON_ARGS[0])) return NULL;

  file = _FCT_ANON_ARGS[0];
  version = get_kb_item("SMB/FileVersions"+tolower(str_replace(string:file, find:"\", replace:"/")));
  if (isnull(version))
  {
    fh = CreateFile(
      file:file,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
    if (!isnull(fh))
    {
      ver = GetFileVersion(handle:fh);
      CloseFile(handle:fh);
      if (!isnull(ver))
      {
        version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
        set_kb_item(
          name:"SMB/FileVersions"+tolower(str_replace(string:file, find:"\", replace:"/")),
          value:version
        );
      }
    }
  }
  return version;
}

function version_cmp(a, b)
{
 local_var i;

 a = split(a, sep:'.', keep:FALSE);
 b = split(b, sep:'.', keep:FALSE);

 for ( i = 0; i < max_index(a) ; i ++ )
 {
  if ( int(a[i]) < int(b[i]) )
	return -1;
  else if ( int(a[i]) > int(b[i]) )
	return 1;
 }
  return 0;
}


vuln = 0;
office_version = hotfix_check_office_version ();
office_sp = get_kb_item("SMB/Office/SP");
sqlpath = get_kb_item("mssql/path");
sqledition = get_kb_item("mssql/edition");
visiopath = get_kb_item("SMB/Office/VisioPath");
progfiles = hotfix_get_programfilesdir();
cdir = hotfix_get_commonfilesdir();

# Look in the registry for install info on a few of the apps being tested
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to remote registry.");
}

# Detect Visual Studio 2005 installs
key = "SOFTWARE\Microsoft\VisualStudio\8.0";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"InstallDir");
  if (!isnull(item))
  {
    vs2005_path = item[1];
    vs2005_root = ereg_replace(
      pattern:"^(.+)\\Common7\\IDE\\$", replace:"\1", string:vs2005_path,
      icase:TRUE
    );
  }

  RegCloseKey(handle:key_h);
}

# Detect Visual FoxPro installs
vfp8key = "SOFTWARE\Microsoft\VisualFoxPro\8.0\Setup\VFP";
vfp8key_h = RegOpenKey(handle:hklm, key:vfp8key, mode:MAXIMUM_ALLOWED);
if (!isnull(vfp8key_h))
{
  item = RegQueryValue(handle:vfp8key_h, item:"ProductDir");
  if (!isnull(item)) vfp8_path = item[1];

  RegCloseKey(handle:vfp8key_h);
}

vfp9key = "SOFTWARE\Microsoft\VisualFoxPro\9.0\Setup\VFP";
vfp9key_h = RegOpenKey(handle:hklm, key:vfp9key, mode:MAXIMUM_ALLOWED);
if (!isnull(vfp9key_h))
{
  item = RegQueryValue(handle:vfp9key_h, item:"ProductDir");
  if (!isnull(item)) vfp9_path = item[1];

  RegCloseKey(handle:vfp9key_h);
}

RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

if (!is_accessible_share(share:share)) exit(1, "is_accessible_share() failed.");

r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 )
{
  NetUseDel();
  exit(1, "Can't connect to '"+share+"' share.");
}

# IE 6 on Windows 2000 SP4 (KB958869)
if (hotfix_is_vulnerable(os:"5.0", sp:4, file:"Vgx.dll", version:"6.0.2800.1637", min_version:"6.0.0.0", dir:"\Microsoft Shared\VGX", path:cdir))
{
  vuln++;
}

# Visio 2002 (KB975365)
if (
  visiopath &&
  hotfix_is_vulnerable(file:"visio.exe", version:"10.0.6885.4", min_version:"10.0.0.0", path:visiopath, dir:"\Visio10")
)
{
  vuln++;
}

msoxp_path = cdir + "\Microsoft Shared\Office10";

# The fixes for Office XP SP3 and Visual Studio.NET SP1 both update the same
# exact file.  The Office fix supersedes the VS .NET fix.
if ("10.0" >< office_version && office_sp == 3)
{
  # Office XP SP3 (KB974811)
  if(hotfix_is_vulnerable(file:"mso.dll", version:"10.0.6856.0", path:msoxp_path))
  {
    vuln++;
  }
}
else
{
  # Visual Studio .NET 2003 SP1 (KB971022).  The 'min_version' arg is used to
  # prevent from firing on Office XP < SP3
  if(hotfix_is_vulnerable(file:"mso.dll", version:"10.0.6855.0",   min_version:"10.0.6802.0", path:msoxp_path))
  {
    vuln++;
  }
}

# Office 2003 SP3 (KB972580)
if ("11.0" >< office_version && office_sp == 3)
{
  path = hotfix_get_officeprogramfilesdir() + "\Microsoft Office\OFFICE11";

  if (hotfix_is_vulnerable(file:"Gdiplus.dll", version:"11.0.8312.0",       min_version:"11.0.0.0", path:path))
  {
    vuln++;
  }
}

# Office 2007 SP1 and SP2 (KB972581)
if ("12.0" >< office_version && (office_sp == 1 || office_sp == 2))
{
  path = hotfix_get_commonfilesdir() + "\Microsoft Shared\OFFICE12";

  if (hotfix_is_vulnerable(file:"Ogl.dll", version:"12.0.6509.5000", path:path))
  {
    vuln++;
  }
}

# Visual FoxPro and the .NET Framework are only vulnerable on Windows 2000
if (hotfix_check_sp(win2k:6))
{
  if (
    # Visual FoxPro 8.0 SP1 (KB971104)
    hotfix_is_vulnerable(path:vfp8_path, file:"gdiplus.dll", version:"5.2.6001.22319") ||

    # Visual FoxPro 9.0 SP2 (KB971105)
    hotfix_is_vulnerable(path:vfp9_path, file:"gdiplus.dll", version:"5.2.6001.22319") ||
    
    # .NET Framework 1.1 SP1 (KB971108)
    hotfix_is_vulnerable(dir:"\Microsoft.Net\Framework\v1.1.4322", file:"gdiplus.dll", version:"5.2.6001.22319", min_version:"5.1.3102.1360") ||
    
    # .NET Framework 2.0 SP1 (KB971110) and SP2 (KB971111)
    hotfix_is_vulnerable(dir:"\Microsoft.Net\Framework\v2.0.50727", file:"gdiplus.dll", version:"5.2.6001.22319", min_version:"5.1.3102.1355")
  )
  {
    vuln++;
  }
}

# Visual Studio 2005 SP1 (KB971023)
if (vs2005_root)
{
  path = vs2005_root + '\\SDK\\v2.0\\BootStrapper\\Packages\\ReportViewer';

  if (hotfix_is_vulnerable(file:"reportviewer.exe", version:"2.0.50727.4401", min_version:"2.0.50727.0", path:path))
  {
    vuln++;
  }
}

# Visual Studio 2008
if (progfiles)
{
  path = progfiles + '\\Microsoft SDKs\\Windows\\v6.0A\\Bootstrapper\\Packages\\ReportViewer';

  if (
    # Visual Studio 2008 (KB972221)
    hotfix_is_vulnerable(file:"reportviewer.exe", version:"9.0.21022.227", min_version:"9.0.21022.0", path:path) ||

    # Visual Studio 2008 SP1 (KB972222)
    hotfix_is_vulnerable(file:"reportviewer.exe", version:"9.0.30729.4402", min_version:"9.0.30729.0", path:path)
  )
  {
    vuln++;
  }
}

# SQL server 2005 (excluding Express Edition)
if (
  sqlpath &&
  sqledition && "Express" >!< sqledition &&

  (
  # SP3 (KB970892 & KB970894)
  hotfix_is_vulnerable(path:sqlpath, file:"Sqlservr.exe", version:"2005.90.4262.0", min_version:"2005.90.4200.0") ||
  hotfix_is_vulnerable(path:sqlpath, file:"Sqlservr.exe", version:"2005.90.4053.0", min_version:"2005.90.4000.0") ||

  # SP2 (KB970895 & KB970896)
  hotfix_is_vulnerable(path:sqlpath, file:"Sqlservr.exe", version:"2005.90.3353.0", min_version:"2005.90.3200.0") ||
  hotfix_is_vulnerable(path:sqlpath, file:"Sqlservr.exe", version:"2005.90.3080.0", min_version:"2005.90.3000.0")
  )
)
{
  vuln++;
}

# SQL server 2000 reporting services SP2 (KB970899)
if (sqlpath)
{
  sqlsrs_path = ereg_replace(
    pattern:"^(.*)\\Binn\\?",
    replace:"\1\Reporting Services\ReportServer\bin",
    string:sqlpath,
    icase:TRUE
  );
  if (hotfix_is_vulnerable(path:sqlsrs_path, file:"ReportingServicesLibrary.dll", version:"8.0.1067.0"))
  {
    vuln++;
  }
}

# If any of the above applications are vulnerable, there's no need to check
# the WinSxS dir (for the OS-specific patches
if (vuln)
{
  set_kb_item(name:"SMB/Missing/MS09-062", value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}

# KB958869.  Checks the SxS directory.  The bulletin says 2k, vista/2k8 SP2,
# and win7 aren't affected
if (hotfix_check_server_core() == 1) exit(0, "Windows Server Core installs are not affected.");
if (hotfix_check_sp(xp:4, win2003:3, vista:2) <= 0) exit(0, "The host is not affected based on its version / service pack.");

patched = FALSE;
winsxs = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\WinSxS", string:rootfile);
files = list_dir(basedir:winsxs, level:0, dir_pat:"microsoft.windows.gdiplus", file_pat:"^gdiplus\.dll$");

if (!isnull(files) && max_index(files) > 0 )
{
  # When the patched DLL is added to the SxS dir, the older (vulnerable)
  # versions of the file remain in the SxS dir.  This checks to see if there is
  #  _any_ gdiplus.dll that has been patched
  foreach file (files)
  {
    ver = get_file_version(file);
    if ( hotfix_check_sp(xp:4, win2003:3) > 0 && version_cmp(a:ver, b:"5.2.6001.22319") >= 0 ) patched = TRUE;
    if ( hotfix_check_sp(vista:2) > 0 && version_cmp(a:ver, b:"5.2.6001.22319") >= 0 && version_cmp(a:ver, b:"6.0.0.0") < 0 ) patched = TRUE;
    if ( hotfix_check_sp(vista:2) > 0 && version_cmp(a:ver, b:"6.0.6001.18175") >= 0 && version_cmp(a:ver, b:"6.0.6001.20000") < 0 ) patched = TRUE;
    if ( hotfix_check_sp(vista:2) > 0 && version_cmp(a:ver, b:"6.0.6001.22319") >= 0 && version_cmp(a:ver, b:"6.0.6001.99999") < 0 ) patched = TRUE;
    if ( hotfix_check_sp(vista:2) > 0 && version_cmp(a:ver, b:"6.0.6000.16782") >= 0 && version_cmp(a:ver, b:"6.0.6000.20000") < 0 ) patched = TRUE;
    if ( hotfix_check_sp(vista:2) > 0 && version_cmp(a:ver, b:"6.0.6000.20966") >= 0 && version_cmp(a:ver, b:"6.0.6000.99999") < 0 ) patched = TRUE;
    if ( patched ) break;
  }

  if (!patched)
  {
    winsxs = string(rootfile, '\\WinSxS');
    report = string(
      "\n",
      "None of the versions of 'gdiplus.dll' under ", winsxs, "\n",
      "have been patched.\n"
    );
    set_kb_item(name:"SMB/Missing/MS09-062", value:TRUE);
    security_hole(port:port, extra:report);
    hotfix_check_fversion_end();
    exit(0);
  }
}

hotfix_check_fversion_end();
exit(0, "The host is not affected.");

