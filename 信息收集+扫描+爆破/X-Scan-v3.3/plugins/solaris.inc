#
# (C) Tenable Network Security
#
# $Id: solaris.inc,v 1.13 2009/03/20 14:55:13 theall Exp $
# 
# @NOGPL@
#

global_var report;
global_var details;
report = NULL;
details = NULL;

function solaris_get_report()
{
 local_var ret;

 ret = report;
 if ( strlen(details) )
   ret += '\nList of affected packages :\n' + details;

 return ret;
}

function solaris_report_set()
{
 report = _FCT_ANON_ARGS[0] + '\n';
}


function solaris_details_add()
{
 details += _FCT_ANON_ARGS[0] + '\n';
}



function maj_vers_cmp()
{
 local_var a, b, i;
 local_var m;

 a = _FCT_ANON_ARGS[0];
 b = _FCT_ANON_ARGS[1];
 a = split(a, sep:".", keep:FALSE);
 b = split(b, sep:".", keep:FALSE);
 return int(a[0]) - int(b[0]);
}

function vers_cmp()
{
 local_var a, b, i;
 local_var m;

 a = _FCT_ANON_ARGS[0];
 b = _FCT_ANON_ARGS[1];
 a = split(a, sep:".", keep:FALSE);
 b = split(b, sep:".", keep:FALSE);
 m = max_index(a);
 if ( max_index(b) < m ) m = max_index(b);

 for ( i = 0 ; i < m; i ++ )
 {
  if ( a[i] != b[i] )
	return int(a[i]) - int(b[i]);
 }

 
 return max_index(a) - max_index(b);
}


function sol_vers_cmp()
{
 local_var a, b, i;
 local_var n, t;
 local_var a_maj, b_maj, a_min, b_min;

 a = _FCT_ANON_ARGS[0];
 b = _FCT_ANON_ARGS[1];
 if ( isnull(a) || isnull(b) ) return -1;

 if ( "," >< a   )
 {
   t = split(a, sep:',', keep:FALSE);
   a_maj = t[0]; 
   a_min = t[1];
 }
 else a_maj = a;

 if ( "," >< b  )
 {
   t = split(b, sep:',', keep:FALSE);
   b_maj = t[0]; 
   b_min = t[1];
 }
 else b_maj = b;



 #
 # If the major version is not the same
 # do not do anything
 #
 n = vers_cmp(a_maj, b_maj);
 if ( n != 0 ) return 1;


 if ( isnull(a_min) )
	{	
	 if ( isnull(b_min) ) return 0;
	 else return 1;	# b is newer
	}

 if ( isnull(b_min) ) 
	return -1; # a is newer

 if ( a_min =~ "REV=" && b_min =~ "REV=" )
 {
   a = str_replace(find:"REV=", replace:"", string:a_min);
   b = str_replace(find:"REV=", replace:"", string:b_min);
   if ( maj_vers_cmp(a,b) != 0 ) return 1;
   n = vers_cmp(a,b);
   return n;
 }
 else if ( a_min =~ "PATCH=" && b_min =~ "PATCH=" )
 {
   a = str_replace(find:"PATCH=", replace:"", string:a_min);
   b = str_replace(find:"PATCH=", replace:"", string:b_min);
   n = vers_cmp(a,b);
   return n;
 }
 else return 0; # ????????????
  

 
 
}

function patch_installed(showrev, patch)
{
 local_var v, p,r,patches,spatches, flag;
 v = split(patch, sep:"-", keep:0);
 patches = egrep(pattern:"^Patch: " + v[0], string:showrev);
 if ( ! patches ) return 0; # No patch
#
# there may be more then one patch version be listed, so split up the result
# and do a foreach check.
#
 spatches = split(patches, keep:0); 
 flag = 0;
 foreach r (spatches)
	{
 	# Get the revision number of the installed patch
 	r = ereg_replace(pattern:"Patch: ([0-9]*-[0-9]*) .*", replace:"\1", string:r);
 	p = split(r, sep:"-", keep:0);
 	# If the installed patch is newer than or equal to what we expect, consider
 	# it installed
 
 	if  ( int(p[1]) >= int(v[1]) ) 
	flag = 1; # Patch is installed
	}
return flag;	
}

function patch_release_number(showrev, patch)
{
 local_var p, installed;
 local_var line, p2;
 local_var max, imax;
 p = split(patch, sep:'-');
 max = 0;
 installed = egrep(pattern:"^Patch: " + p[0], string:showrev);
 if ( installed )
 {
  foreach line ( split(installed) )
  {
   p = ereg_replace(pattern:"^Patch: ([0-9-]*) .*", string:line, replace:"\1");
   p2 = ereg_replace(pattern:"[0-9]*-([0-9])", string:p, replace:"\1");
   if ( int(p2) > imax ) { imax = int(p2); max = p; }
  }
  return chomp(max);
 }
 else return NULL;
}


#
# solaris_check_patch() returns :
#	-1 if a patch is missing
#	0  if a patch is not installed but not required (ie: other architecture) or
#          installed
#
function solaris_check_patch(release, arch, patch, package, obsoleted_by, version) 
{
 local_var showrev, r, flag, packages, obs, p;

 if ( "_x86" >< release )
	release -= "_x86";

 showrev = get_kb_item("Host/Solaris/showrev");
 if (  ! showrev || !release || !patch ) return 0;

 # Look if at least one of the packages installed are affected
 # by this patch
 flag = 0;
 if ( strlen(package) )
 {
  packages = split(package, sep:" ", keep:FALSE);
  foreach p (packages)
	{
  	if ( get_kb_item("Solaris/Packages/Versions/" + p ) ) flag ++;
	}

 } else flag = 1;

 # No package is affected  - return
 if ( flag == 0 ) return 0;


 r = split(release, sep:" ", keep:0);
 flag = 0;
 foreach release (r)
 {
 if ( egrep(pattern:"^Release: " + release, string:showrev) ) flag ++;
 }

 if ( ! flag ) return 0; # Not the right release

 if ( ! egrep(pattern:"^Application architecture: " + arch, string:showrev) ) 
	return 0; # Wrong architecture (intel vs. sparc)

 if ( patch_installed(patch:patch, showrev:showrev) )
	return 0; # Installed

 if ( obsoleted_by )
 {
  obs = split(obsoleted_by, sep:" ", keep:FALSE);
  foreach p ( obs )
  {
    if ( patch_installed(patch:p, showrev:showrev) || "OBSOLETE" >< p ) 
	return 0; # Installed
  }
 }

 if ( ! isnull(version) )
 {
  if ( sol_vers_cmp(get_kb_item("Solaris/Packages/Versions/" + package), version) > 0 ) return 0; # Installed
 }

 
 r = NULL;
 r = 'Missing patch : ' + patch;
 if ( patch_release_number(showrev:showrev, patch:patch) )
  r += ' (Current revision : ' + patch_release_number(showrev:showrev, patch:patch) + ')';
 else 
  r += ' (No previous revision of this patch has been installed)';


 if ( strlen(obsoleted_by) )
  r += '\n (This patch has been obsoleted by ' + obsoleted_by + ' which is not installed)\n';

 solaris_report_set(r);
 
 r = '- ' + package + ', version : ' + get_kb_item("Solaris/Packages/Versions/" + package);
 


 solaris_details_add(r);

 
  
 
 return -1; # Not installed
}


