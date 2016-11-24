#
# (C) Tenable Network Security, Inc.
#
# $Id: rpm.inc,v 1.40 2009/11/02 22:11:38 theall Exp $
#
# @NOGPL@
#

global_var rpm_report;

rpm_report = '';

function filter_rh_inconstency()
{
 local_var a;
 a = _FCT_ANON_ARGS[0];
 if ( tolower(a) =~ "^rhel[0-9.]+$" )
  a = ereg_replace(pattern:"^rhel", replace:"el", string:a, icase:TRUE);

 return a;
}

function rpm_report_add(package, reference)
{
 local_var array;
 array = split(package, sep:'|', keep:FALSE);
 package = array[0];
 rpm_report += 'Remote package installed : ' + package + '\n' +
		'Should be : ' + reference + '\n';
 
}


function rpm_report_get()
{
  if ( strlen(rpm_report) )
	 return '\n' + rpm_report;
 else
	return NULL;
}

function parse_rpm_name(rpm, yank)
{
 local_var elems, num, i, name;
 local_var my_rpm;

 elems = split(rpm, sep:"|", keep:0);
 if ( max_index(elems) > 1 )
 {
  my_rpm["epoch"] = elems[1];
#  my_rpm["keyid"] = elems[2];
  rpm = elems[0];
 }
 elems = split(rpm, sep:"-", keep:0);
 num = max_index(elems);
 name = elems[0];
 for ( i = 1; i < num - 2 ; i ++ )
 {
  name += "-" + elems[i];
 }

 
 my_rpm["name"]     = name;
 my_rpm["version"]  = elems[num - 2];
 my_rpm["release"] = elems[num - 1];

 if ( yank ) {
	my_rpm["version"]  -= yank;
        my_rpm["release"] -= yank;
        my_rpm["epoch"] -= yank;
 }

 return my_rpm;
}

function maj_cmp(a, b)
{
 local_var array_a, array_b, i, max;
 local_var e;

 array_a = split(a, sep:".", keep:0);
 array_b = split(b, sep:".", keep:0);
 
 
 return int(array_a[0]) - int(array_b[0]);
}


function normalize_value()
{
 local_var val;

 val = _FCT_ANON_ARGS[0];

 if ( val == ord(" ") ) return 0;
 if ( val >= ord("0") && val <= ord("9") )
	val += 255;
 return val;
}
function generic_str_cmp(a,b)
{
 local_var n, i, val_a, val_b;
 local_var retval;


 if ( strlen(a) < strlen(b) )
   a = strcat(a, crap(data:'\x00', length:strlen(b) - strlen(a)));
 else if ( strlen(a) > strlen(b) )
   b = strcat(b, crap(data:'\x00', length:strlen(a) - strlen(b)) );

 n = strlen(a);
 retval = 0;
 for ( i = 0 ; i < n ; i ++ )
 {
   val_a = normalize_value(ord(a[i])); 
   val_b = normalize_value(ord(b[i])); 
   if ( val_a > val_b )
	return 1;
   else if ( val_a < val_b )
	return -1;
 }
 
 return 0;
}


function nondigit_vers_cmp(a,b)
{
 local_var ia, ib;
 local_var aa, ab;
 local_var s;

 if ( a =~ "^[0-9]" && b !~ "^[0-9]" )
	return 1;
 else if ( b =~ "^[0-9]" && a !~ "^[0-9]" )
	return -1;

 if ( a =~ "^[0-9]" && b =~ "^[0-9]" )
 {
  aa = eregmatch(string:a, pattern:"^([0-9]*)(.*)$");
  ab = eregmatch(string:b, pattern:"^([0-9]*)(.*)$");
  ia = int(aa[1]);
  a = aa[2];
 
  ib = int(ab[1]);
  b = ab[2];
  s = 1;
 }
 else if (a =~ "^[^0-9]+[0-9]+$" && b =~ "^[^0-9]+[0-9]+$" )
 {
  aa = eregmatch(string:a, pattern:"^([^0-9]*)([0-9]*)$");
  ab = eregmatch(string:b, pattern:"^([^0-9]*)([0-9]*)$");
  ia = int(aa[2]);
  a = aa[1];
 
  ib = int(ab[2]);
  b = ab[1];
  s = 2;
  if ( a < b ) 
	return -1;
  else if ( a > b ) 
	return 1;
 }
 else
 {
  return generic_str_cmp(a:a,b:b);
 } 

 if ( strlen(aa[s]) && strlen(ab[s]) )
 {
 if ( ia < ib ) 
	return -1;
 else if ( ia > ib )
	return 1;
 }

 if ( strlen(a) != 0 && strlen(b) == 0 ) return 1;
 if ( strlen(b) != 0 && strlen(a) == 0 ) return -1;

 if ( a < b ) 
	return -1;
 else if ( a > b ) 
	return 1;
 else
	return 0;
}


function vers_cmp(a, b)
{
 local_var array_a, array_b, i, max;
 local_var digit_mode_a, digit_mode_b;
 local_var elem_a, elem_b, j, la, lb;

 array_a = split(tolower(a), sep:".", keep:0);
 array_b = split(tolower(b), sep:".", keep:0);
 
 if ( max_index(array_b) < max_index(array_a))
	max = max_index(array_a);
 else
	max = max_index(array_b);

 for ( i = 0 ; i < max ; i ++ )
 {
  digit_mode_a = 1;
  digit_mode_b = 1;
  if ( max_index(array_a) <= i ) return -1;
  if ( max_index(array_b) <= i ) return 1;

  array_a[i] = filter_rh_inconstency(array_a[i]);
  array_b[i] = filter_rh_inconstency(array_b[i]);

  elem_a = array_a[i];
  elem_b = array_b[i];
  la = strlen(elem_a);
  lb = strlen(elem_b);
  for (j=0; j<la && j<lb; j++)
  {
   if (elem_a[j] != elem_b[j]) break;
  }
  if (j > 0)
  {
   if (j == la || j == lb) j--;
   array_a[i] = substr(elem_a, j);
   array_b[i] = substr(elem_b, j);
  }

  if ( array_a[i] !~ "^[0-9]+$" ) digit_mode_a = 0;
  if ( array_b[i] !~ "^[0-9]+$" ) digit_mode_b = 0;

  if ( digit_mode_a && digit_mode_b )
      {
       if ( int(array_a[i]) != int(array_b[i]) )
         return int(array_a[i]) - int(array_b[i]);
      }
  else if ( array_a[i] != array_b[i] )
     {
        if ( nondigit_vers_cmp(a:array_a[i], b:array_b[i]) < 0 )
	  return -1;
 	else 
	  return  1;
     }
 }

 return 0;
}


function rpm_cmp(rpm, reference, yank, epoch)
{
 local_var my_rpm, my_reference, eq, ep;

 my_rpm = parse_rpm_name(rpm:rpm, yank:yank);
 my_reference = parse_rpm_name(rpm:reference, yank:yank);

 if ( epoch )
  {
   eq = int(my_rpm["epoch"]) - int(epoch);
   if ( eq  ) return eq;
  }

 eq = maj_cmp(a:my_rpm["version"], b:my_reference["version"]);
 if ( eq != 0 ) return 0;

 eq = vers_cmp(a:my_rpm["version"], b:my_reference["version"]);
 if ( eq ) return eq;
 
 return vers_cmp(a:my_rpm["release"], b:my_reference["release"]);
}



function rpm_check(prefix, reference, yank, release, epoch, cpu)
{
 local_var rh_release, rpms, package, lines, e, my_rpm, ok, suse_release, mdk_release, centos_release, flag;
 local_var my_cpu;

 if ( "kernel-doc" >< reference ) return 0;
 rh_release = get_kb_item("Host/RedHat/release");
 suse_release = get_kb_item("Host/SuSE/release");
 mdk_release = get_kb_item("Host/Mandrake/release");
 centos_release = get_kb_item("Host/CentOS/release");

 if ( ! isnull(cpu) )
 {
  my_cpu = get_kb_item("Host/cpu");
  if ( my_cpu != cpu ) 
  {
    if (my_cpu =~ "i[3-6]86" && cpu =~ "i[3-6]86")
    {
      if (int(substr(my_cpu, 1)) < int(substr(cpu, 1))) return 0;
    }
    else return 0;
  }
 }
 if ( release )
 {
  flag = 0;
  if ( "MDK" >< release && release == mdk_release ) flag ++;
  else if ( "SUSE" >< release && release == suse_release ) flag ++;
  else if ( "SLED" >< release && release == suse_release ) flag ++;
  else if ( "SLES" >< release && release == suse_release ) flag ++;
  else if ( release == "RHEL5" && egrep(pattern:"Red Hat Enterprise Linux.*release 5", string:rh_release) ) flag ++;
  else if ( release == "RHEL4" && egrep(pattern:"Red Hat Enterprise Linux.*release 4", string:rh_release) ) flag ++;
  else if ( release == "RHEL3" && egrep(pattern:"Red Hat Enterprise Linux.*release 3", string:rh_release) ) flag ++;
  else if ( release == "RHEL2.1" && egrep(pattern:"Red Hat.*(Enterprise|Advanced).*release 2\.1", string:rh_release) ) flag ++;
  else if ( release == "FC1" && "Fedora Core release 1" >< rh_release ) flag ++;
  else if ( release == "FC2" && "Fedora Core release 2" >< rh_release ) flag ++;
  else if ( release == "FC3" && "Fedora Core release 3" >< rh_release ) flag ++;
  else if ( release == "FC4" && "Fedora Core release 4" >< rh_release ) flag ++;
  else if ( release == "FC5" && "Fedora Core release 5" >< rh_release ) flag ++;
  else if ( release == "FC6" && "Fedora Core release 6" >< rh_release ) flag ++;
  else if ( release == "FC7" && "Fedora release 7" >< rh_release ) flag ++;
  else if ( release == "FC8" && "Fedora release 8" >< rh_release ) flag ++;
  else if ( release == "FC9" && "Fedora release 9" >< rh_release ) flag ++;
  else if ( release == "FC10" && "Fedora release 10" >< rh_release ) flag ++;
  else if ( release == "FC11" && "Fedora release 11" >< rh_release ) flag ++;
  else if ( release == "FC12" && "Fedora release 12" >< rh_release ) flag ++;
  else if ( release == "CentOS-3" && "CentOS release 3" >< centos_release ) flag ++;
  else if ( release == "CentOS-4" && "CentOS release 4" >< centos_release ) flag ++;
  else if ( release == "CentOS-5" && "CentOS release 5" >< centos_release ) flag ++;

  if ( flag != 1 ) return 0;
 }
 else if ( ! egrep(pattern:"Red Hat.*(Enterprise|Advanced).*release", string:rh_release) ) return 0;

 if ( "SUSE" >< release || "SLED" >< release || "SLES" >< release ) 
 	rpms = get_kb_item("Host/SuSE/rpm-list");
 else if ("MDK" >< release)
	rpms = get_kb_item("Host/Mandrake/rpm-list");
 else if ( "CentOS" >< release )
	rpms = get_kb_item("Host/CentOS/rpm-list");
 else
	rpms = get_kb_item("Host/RedHat/rpm-list");

 if ( ! rpms ) return 0;


 if ( prefix )
  {
  if ( "kernel-" == prefix )
      package = egrep(pattern:"^kernel-([0-9]|unsupported|source|smp|hugemem|doc|BOOT)", string:rpms);
    else 
      package = egrep(pattern:"^" + prefix + "([0-9]|devel|libs|utils|common|core|client|server)", string:rpms);
  }
 else
 {
  my_rpm = parse_rpm_name(rpm:reference, yank:yank);
  package = egrep(pattern:"^" + my_rpm["name"] + "-[0-9]", string:rpms);
 }
  
 if ( ! package ) return 0;
 lines = split(package, sep:'\n', keep:0);
 foreach package (lines)
 {
	 e =  rpm_cmp(rpm:package, reference:reference, yank:yank, epoch:epoch);
	 if ( e < 0 )
		{
		rpm_report_add(package:package, reference:reference);
		 if ( "kernel-" >!< reference )
			return 1;
		}
		else ok = 1;
 }

 if ( "kernel-" >!< reference )
	return 0;
 else
	{
	if ( ok ) 
	 {
	  rpm_report = NULL;
	  return 0;
	 }
	else 
         return 1;
	}
}


function rpm_exists(rpm, release)
{
 local_var rh_release,suse_release, mdk_release, rpms, package, lines, e, my_rpm, centos_release, ok;

 rh_release = get_kb_item("Host/RedHat/release");
 suse_release = get_kb_item("Host/SuSE/release");
 mdk_release = get_kb_item("Host/Mandrake/release");
 centos_release = get_kb_item("Host/CentOS/release");

 if ( release )
 {
  if ( "MDK" >< release && release != mdk_release ) return 0;
  if ( "SUSE" >< release && release != suse_release) return 0;
  if ( "SLES" >< release && release != suse_release) return 0;
  if ( "SLED" >< release && release != suse_release) return 0;
  if ( release == "RHEL5" && !egrep(pattern:"Red Hat Enterprise Linux.*release 5", string:rh_release) ) return 0;
  if ( release == "RHEL4" && !egrep(pattern:"Red Hat Enterprise Linux.*release 4", string:rh_release) ) return 0;
  if ( release == "RHEL3" && !egrep(pattern:"Red Hat Enterprise Linux.*release 3", string:rh_release) ) return 0;
  if ( release == "RHEL2.1" && !egrep(pattern:"Red Hat.*(Enterprise|Advanced).*release 2\.1", string:rh_release) ) return 0;
  if ( release == "FC1" && "Fedora Core release 1" >!< rh_release ) return 0;
  if ( release == "FC2" && "Fedora Core release 2" >!< rh_release ) return 0;
  if ( release == "FC3" && "Fedora Core release 3" >!< rh_release ) return 0;
  if ( release == "FC4" && "Fedora Core release 4" >!< rh_release ) return 0;
  if ( release == "FC5" && "Fedora Core release 5" >!< rh_release ) return 0;
  if ( release == "FC6" && "Fedora Core release 6" >!< rh_release ) return 0;
  if ( release == "FC7" && "Fedora release 7" >!< rh_release ) return 0;
  if ( release == "FC8" && "Fedora release 8" >!< rh_release ) return 0;
  if ( release == "FC9" && "Fedora release 9" >!< rh_release ) return 0;
  if ( release == "FC10" && "Fedora release 10" >!< rh_release ) return 0;
  if ( release == "FC11" && "Fedora release 11" >!< rh_release ) return 0;
  if ( release == "CentOS-3" && "CentOS release 3" >!< centos_release ) return 0;
  if ( release == "CentOS-4" && "CentOS release 4" >!< centos_release ) return 0;
  if ( release == "CentOS-5" && "CentOS release 5" >!< centos_release ) return 0;

 }
 else if ( ! egrep(pattern:"(Red Hat.*(Enterprise|Advanced).*release|Fedora)", string:rh_release) ) return 0;

 if ( "SUSE" >< release || "SLED" >< release || "SLES" >< release ) 
 	rpms = get_kb_item("Host/SuSE/rpm-list");
 else if ("MDK" >< release)
	rpms = get_kb_item("Host/Mandrake/rpm-list");
 else if ("CentOS" >< release )
	rpms = get_kb_item("Host/CentOS/rpm-list");
 else
	rpms = get_kb_item("Host/RedHat/rpm-list");


 if ( ! rpms ) return 0;

 if ( egrep(pattern:"^" + rpm, string:rpms) ) 
	return 1;
  else
	return 0;

}
