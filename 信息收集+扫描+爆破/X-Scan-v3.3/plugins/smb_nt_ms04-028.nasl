#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(14724);
 script_version("$Revision: 1.30 $");

 script_cve_id("CVE-2004-0200");
 script_bugtraq_id(11173);
 script_xref(name:"IAVA", value:"2004-A-0015");
 script_xref(name:"IAVA", value:"2004-t-0028");
 script_xref(name:"OSVDB", value:"9951");

 name["english"] = "MS04-028: Buffer Overrun in JPEG Processing (833987)";

 script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows which is vulnerable to
a buffer overrun attack when viewing a JPEG file that may allow an
attacker to execute arbitrary code on the remote host. 

To exploit this flaw, an attacker would need to send a malformed JPEG file
to a user on the remote host and wait for him to open it using an
affected Microsoft application." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000, XP and
2003 :

http://www.microsoft.com/technet/security/bulletin/ms04-028.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Checks for ms04-028 via the registry";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);

 script_dependencies("smb_hotfixes.nasl" );
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_hotfixes.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");


global_var report;

if ( ! get_kb_item("SMB/Registry/Enumerated" ) ) exit(0);

if ( hotfix_check_sp(xp:2, win2003:1) > 0 ) 
{
if ( hotfix_missing(name:"KB833987") > 0 ) 
	{
	 {
 set_kb_item(name:"SMB/Missing/MS04-028", value:TRUE);
 hotfix_security_hole();
 }
	exit(0);
	}
}

if ( ! thorough_tests ) exit (0);

# Crawl through %ProgramFiles% to get the list of affected files
report = make_list();
function add_file(file, version)
{
 global_var report;

 report = make_list(report, file + " (version " + version[0] + "." + version[1] + "." + version[2] + "." + version[3] + ")");
}


function get_dirs(basedir, level)
{
 local_var ret, subdirs, subsub, array;
 

 if(level > 3)
 	return NULL;
	
 subdirs = NULL;
 ret = FindFirstFile(pattern:basedir + "\*");
 if(isnull(ret))
 	return NULL;


 array = make_list();
	
 while ( ! isnull(ret[1]) )
 { 
  array = make_list(array, basedir + "\" + ret[1]);
  subsub = NULL;
  if("." >!< ret[1])
  	subsub  = get_dirs(basedir:basedir + "\" + ret[1], level:level + 1);
  if(!isnull(subsub))
  {
  	if(isnull(subdirs))subdirs = make_list(subsub);
  	else	subdirs = make_list(subdirs, subsub);
  }

  ret = FindNextFile(handle:ret);
 }
 
 if(isnull(subdirs))
 	return array;
 else
 	return make_list(array, subdirs);
}

		

function list_gdiplus_files()
{
 local_var dir, dirs, gdi_plus_file, num_gdi_plus_files, programfiles, r, share, soc;
 global_var port;

 num_gdi_plus_files = 0;

 programfiles = hotfix_get_programfilesdir();
 if ( ! programfiles ) exit(1);

 soc = open_sock_tcp(port);
 if ( ! soc ) exit(1);

 session_init(socket:soc, hostname:kb_smb_name());
 dir = ereg_replace(pattern:"^[A-Za-z]:\\(.*)", replace:"\1", string:programfiles);
 share = ereg_replace(pattern:"^([A-Za-z]):\\.*", replace:"\1$", string:programfiles);
 gdi_plus_file = NULL;
 
 r = NetUseAdd(login:kb_smb_login(), password:kb_smb_password(), domain:kb_smb_domain(), share:share);
 if ( r != 1 ) exit(1);
 dirs = get_dirs(basedir:dir, level:0);
 foreach dir (dirs)
   {
    if(ereg(pattern:"\\(gdiplus|mso)\.dll", string:dir, icase:TRUE))
    {
     if(isnull(gdi_plus_file)) gdi_plus_file = make_list(dir);
     else gdi_plus_file = make_list(gdi_plus_file, dir);
     num_gdi_plus_files ++;
     if (num_gdi_plus_files >= 10 )
     {
      return gdi_plus_file;
     }
    }
   }  
  return(gdi_plus_file);
}		

function CheckVersion(file)
{
 local_var i, handle, v;
 handle = CreateFile (file:file, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
 if(!isnull(handle))
 {
  v = GetFileVersion(handle:handle);
  CloseFile(handle:handle);
  if ( ! v ) return 0;
  if ( egrep(pattern:"gdiplus\.dll", icase:TRUE, string:file) )
   {
     # Older than 5.x or 5.1
     if ( v[0] < 5 || v[0] == 5 && v[1] < 1 ) add_file(file:file, version:v);
     # < 5.1.310.1355
     else if ( v[0] == 5 && v[1] == 1 && ( v[2] < 3102 || (v[2] == 3102 && v[3] < 1355 ))) add_file(file:file, version:v);
     # < 5.2.3790.136
     else if ( v[0] == 5 && v[1] == 2 && ( v[2] < 3790 || (v[2] == 3790 && v[3] < 136  ))) add_file(file:file, version:v);
     # < 6.0.3264.0
     else if ( v[0] == 6 && v[1] == 0 && v[2] < 3264 ) add_file(file:file, version:v);
   }
   else if ( egrep(pattern:"mso\.dll", icase:TRUE, string:file) )
   {
     # Older than 10.0.6714
     if ( v[0] < 10 || (v[0] == 10 && v[1] == 0 && v[2] < 6714 )) add_file(file:file, version:v);
   }
 }
}


#
# Here we go
#		


port = kb_smb_transport();
name = kb_smb_name();
if(!name)exit(0);




login = kb_smb_login();
pass =  kb_smb_password();
dom = kb_smb_domain();
if(!get_port_state(port))exit(1);
files = list_gdiplus_files();
if(!isnull(files))
 {
  foreach f (files)
  {
   if ( "\Macromedia\" >!< f ) CheckVersion(file:f);
  }
}


NetUseDel();

flag = 0;
foreach file (report)
{
 flag ++;
 str += file + '\n';
}


if ( flag > 0 ) 
{
 report = string (
   "The following files need to be updated :\n\n",
   str
 );
 hotfix_add_report(report);
 {
 set_kb_item(name:"SMB/Missing/MS04-028", value:TRUE);
 hotfix_security_hole();
 }
}
