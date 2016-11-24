#
# $Id: aix.inc,v 1.5 2007/12/03 21:59:52 renaud Exp $
#
# (C) Tenable Network Security
#
# @NOGPL@
#

global_var aix_report;

aix_report = "";

function aix_report_add(installed, required)
{
 aix_report += "Remote package installed : " + str_replace(find:":", replace:".", string:installed) + '\n' +
	       "Should be : "  + required + '\n';

}


function aix_report_get()
{
 if ( strlen(aix_report ) )
	{
	return '\n' + aix_report;
	}
 else
	return NULL;
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


# aix_check_patch() returns :
#	-1 if a patch is missing
#	0  if a patch is not installed but not required (ie: other architecture)
#	1 if the patch is installed
#
# example : aix_check_patch("5.1", "IY55678", "devices.scsi.tape.rte.5.1.0.50 devices.scsi.tape.diag.5.1.0.50");
function aix_check_patch(release, ml, patch, package) 
{
 local_var showrev, v, flag, packages, p, pattern;
 local_var rl;

 rl = chomp(get_kb_item("Host/AIX/oslevel"));
 rl -= "-";
 packages = get_kb_item("Host/AIX/lslpp");
 showrev = get_kb_item("Host/AIX/version");

 if ( ! packages || ! showrev || ( !release && ! ml ) || !patch || !package) return 0;

 if ( ! isnull(release) && release >!< showrev) return 0;
 if ( ! isnull(ml) &&  ml != rl ) return 0;

 package = split(package, sep:" ", keep:FALSE);
 flag=0;
 foreach p (package)
 {
   p = eregmatch(pattern: "^(.*)\.([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", string: p, icase: 0);
   pattern = p[1] + ":([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)";
   v = eregmatch(pattern: pattern , string: packages, icase: 0);
   if (!isnull(v))
   {
     flag = 1;
     if (vers_cmp(v[1], p[2]) < 0)
     {
       aix_report_add(installed:v[0], required:p[0]);
       return -1;
     }
   }
 }

 if (flag)
   set_kb_item(name: "Host/AIX/"+patch, value:1);

 return flag;
}
