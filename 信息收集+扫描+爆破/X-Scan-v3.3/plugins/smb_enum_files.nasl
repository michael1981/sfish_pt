#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(23973);
 script_version ("$Revision: 1.10 $");
 
 name["english"] = "SMB share files enumerated";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"This plugin enumerates files on remote shares." );
 script_set_attribute(attribute:"description", value:
"By connecting to the remote host with the supplied credentials this
plugin enumerates files listed on the remote share and stores the list
in the knowledge base so that it can be used by other plugins." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_end_attributes();
 
 summary["english"] = "Gets the list of files on remote shares";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_accessible_shares.nasl");
 if ( NASL_LEVEL >= 3000 ) script_dependencies("wmi_enum_files.nbin");
 script_require_keys("SMB/shares");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include('global_settings.inc');

# static list of file types 
# that will be written to kbs

file_type_list = make_array(
                        "mp3",1,
                        "doc",1,
                        "txt",1,
                        "pdf",1,
                        "ppt",1,
                        "xls",1,
                        "csv",1,
                        "rtf",1,
                        "mdb",1,
                        "odc",1,
                        "mde",1,
                        "pub",1,
                        "wri",1,
                        "dif",1,
                        "sxw",1,
                        "sxi",1,
                        "sxc",1,
                        "sdw",1,
                        "sdd",1,
                        "sdc",1,
                        "mpg",1,
                       "mpeg",1,
                        "ogg",1,
                        "avi",1,
                        "wma",1,
                       "divx",1,
			"vob", 1);


if ( thorough_tests ) MaxRecursivity = 3;
else MaxRecursivity = 3;

port = kb_smb_transport();

file_count = 0;

function get_dirs(basedir, level)
{
 local_var r, ret, ret2, retx, subdirs, subsub;
 global_var MaxRecursivity;
 

  if(level >= MaxRecursivity )
 	return NULL;
	
 subdirs = NULL;
 retx  = FindFirstFile(pattern:basedir + "\*");
 ret = make_list();
 while ( ! isnull(retx[1]) )
 {
 ret  = make_list(ret, retx[1]);
 retx = FindNextFile(handle:retx);
 } 
 
 if(isnull(ret))
 	return NULL;
	
 foreach r (ret)
 { 
  subsub = NULL;
  if(isnull(ret2))
  	ret2 = make_list(basedir + "\" + r);
  else
  	ret2 = make_list(ret2, basedir + "\" + r);
	
  if("." >!< r)
  	subsub  = get_dirs(basedir:basedir + "\" + r, level:level + 1);
  if(!isnull(subsub))
  {
  	if(isnull(subdirs))subdirs = make_list(subsub);
  	else	subdirs = make_list(subdirs, subsub);
  }
 }
 
 if(isnull(subdirs))
 	return ret2;
 else
 	return make_list(ret2, subdirs);
}

function list_files(share)
{
 local_var dir, dirs, ext, num_suspects, r, suspect;
 global_var login, pass, share;

 num_suspects = 0;

 r = NetUseAdd(login:login, password:pass, share:share);
 if ( r != 1 ) return NULL;
 suspect = NULL;

 dirs = get_dirs(basedir:NULL, level:0);
 if ( ! isnull(dirs) ) 
 foreach dir (dirs)
 {
  if ( '.' >< dir  )
  {
   ext =  ereg_replace(pattern:".*\.([A-za-z1-9]{3,4})$", string:dir, replace:"\1", icase:TRUE);	
   if("clock.avi" >!< tolower(dir) && !ereg(pattern:"^MVI_", string:dir, icase:TRUE) && file_type_list[ext] == 1)
    {
     file_count ++;
     if(isnull(suspect)) suspect = make_list(dir);
     else suspect = make_list(suspect, dir);
   } 
  }
  if ( file_count > 4096 ) break;
 }
 NetUseDel(close:FALSE);
 return(suspect);
}

#
# Here we go
#		


name = kb_smb_name();
login = kb_smb_login();
pass =  kb_smb_password();
dom = kb_smb_domain();

if(!get_port_state(port))exit(1);
shares = get_kb_list("SMB/shares");

if(isnull(shares))exit(0);
else shares = make_list(shares);

soc = open_sock_tcp(port);
if (!soc)
  exit (0);

session_init(socket:soc, hostname:name);

foreach share (shares) 
{
  if ( share != "ADMIN$" && share != "IPC$" )
  {
  files = list_files(share:share);
  if(!isnull(files))
  {
   foreach file (files)
   {
    ext =  ereg_replace(pattern:".*\.([A-za-z1-9]{3,4})$", string:file, replace: "\1");
    if(!isnull(ext) && file_type_list[ext] == 1)
     {		
      set_kb_item(name:"SMB/"+share+"/content/extensions/"+ext, value:file);	
     }	
   }
  }
 }
}
NetUseDel();
