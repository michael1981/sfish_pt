#
# (C) Tenable Network Security
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# See the following licenses for details :
#  http://www.nessus.org/plugins/RegisteredFeed.pdf
#  http://www.nessus.org/plugins/TenableCommercial.pdf
#  http://www.nessus.org/plugins/DirectFeed.pdf
#  http://www.nessus.org/plugins/DirectFeedCommercial.pdf
#
#
# @NOGPL@
#
# freebsd_package.inc 
# $Revision: 1.12 $
#



global_var cvss_score;
# Globals
OPERATOR_GT	=	1;
OPERATOR_GTE	=	2;
OPERATOR_LT	=	3;
OPERATOR_LTE	=	4;
OPERATOR_EQ	=	5;


function parse_pkg_name(pkg)
{
 local_var elems, num, i, name, version;
 local_var my_pkg;

 elems = split(pkg, sep:" ", keep:0);
 num = max_index(elems);
 elems = split(elems[0], sep:"-", keep:0);

 name = elems[0];

 for ( i = 1 ; i < max_index(elems) - 1 ; i ++ )
 {
 name += "-" + elems[i];
 }

 version = split(elems[i], sep:"_", keep:0);
 if ( version[0] == elems[i] ) version = split(elems[i], sep:"p", keep:0);
 if ( version[0] == elems[i] ) version = split(elems[i], sep:",", keep:0);
 
 my_pkg["name"]     = name;
 my_pkg["version"]  = version[0];
 my_pkg["revision"] = version[1];

 return my_pkg;
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
 else
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


function vers_cmp(a, b, release_diff)
{
 local_var array_a, array_b, i, max;
 local_var digit_mode_a, digit_mode_b;
 
 if ( ! a &&  b  ) return -1;
 if (  a &&  ! b  ) return 1;
 if ( ! a && ! b ) return 0;
 a = str_replace(find:"_", replace:".", string:a);
 b = str_replace(find:"_", replace:".", string:b);
 array_a = split(tolower(a), sep:".", keep:0);
 array_b = split(tolower(b), sep:".", keep:0);

 #
 # Make sure this is the same kind of version #
 #
 if ( max_index(array_a) == 1 && 
      max_index(array_b) >  1 ) return 0;

 if ( max_index(array_b) == 1 && 
      max_index(array_a) > 1 ) return 0;


 
 if ( max_index(array_b) < max_index(array_a))
        max = max_index(array_a);
 else
        max = max_index(array_b);

 for ( i = 0 ; i < max ; i ++ )
 {
  if ( i > 2 && release_diff > 0 ) return 1;
  digit_mode_a = 1;
  digit_mode_b = 1;
  if ( max_index(array_a) <= i ) return -1;
  if ( max_index(array_b) <= i ) return 1;

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


function pkg_cmp(pkg, reference)
{
 local_var my_pkg, my_reference, eq;


 if ( strlen(pkg) == 0 || strlen(reference) == 0) return 0;

 my_pkg = parse_pkg_name(pkg:pkg);
 my_reference = parse_pkg_name(pkg:reference);

 eq = vers_cmp(a:my_pkg["version"], b:my_reference["version"], release_diff:vers_cmp(a:my_pkg["revision"], b:my_reference["revision"]));
 if ( eq ) return eq;
	
 
 if ( !isnull(my_reference["revision"]) &&
      isnull(my_pkg["revision"])  ) return -1;


 eq = vers_cmp(a:my_pkg["revision"], b:my_reference["revision"]);
 return eq; 
}






function pkg_op(str)
{
 if ( strlen(str) == 0 ) return 0;
 if ( str[0] == ">" && str[1] == "=" ) return OPERATOR_GTE; 
 else if ( str[0] == ">" ) return OPERATOR_GT; 
 else if ( str[0] == "=" ) return OPERATOR_EQ; 
 else if ( str[0] == "<" && str[1] == "=") return OPERATOR_LTE;
 else if ( str[0] == "<" ) return OPERATOR_LT;
 else return -1;
}

function pkg_op_match(op, n)
{
 if ( (op == OPERATOR_GT || op == OPERATOR_GTE) && n > 0 ) return 1;
 if ( (op == OPERATOR_LT || op == OPERATOR_LTE) && n < 0 ) return 1;
 if ( (op == OPERATOR_EQ || op == OPERATOR_LTE || op == OPERATOR_GTE ) && n == 0 ) return 1;
 return 0;
}

function freebsd_packages()
{
 return get_kb_item("Host/FreeBSD/pkg_info");
}

function pkg_test(pkg, problem, url, seealso)
{
 local_var pkg_name, orig, op1, op2, op1_arg, op2_arg, n, pkgs, package, report;

 pkgs = freebsd_packages();
 if ( ! pkgs ) exit(0, 'Empty list of FreeBSD packages');
 
 orig = pkg;

 pkg_name = ereg_replace(pattern:"([^<>=]*).*", string:pkg, replace:"\1");
 if ( pkg_name == "FreeBSD" ) return 0; # TBD
 pkg -= pkg_name;

 pkg_name = str_replace(find:"{", replace:"(", string:pkg_name);
 pkg_name = str_replace(find:"}", replace:")", string:pkg_name);
 pkg_name = str_replace(find:",", replace:"|", string:pkg_name);


 op1     = pkg_op(str:pkg);
 if (op1 < 0 )
 {
   #display(orig, " -- unsupported operator\n");
   return 0;
 }
 else if ( op1 > 0 ) op1_arg = ereg_replace(pattern:"^[<>=]*([^<>=]*).*", string:pkg, replace:"\1");

 pkg     = ereg_replace(pattern:"^[<>=]*([^<>=]*)(.*)", string:pkg, replace:"\2");
 op2     = pkg_op(str:pkg);
 if (op1 < 0 )
 {
   #display(orig, " -- unsupported operator\n");
   return 0;
 } else if ( op1 > 0 ) op2_arg = ereg_replace(pattern:"^[<>=]*([^<>=]*).*", string:pkg, replace:"\1");



 package = egrep(pattern:"^" + pkg_name + "-", string:pkgs);
 if (  ! package ) return 0;

 n = pkg_cmp(pkg:package, reference:pkg_name + "-" + op1_arg);
 if ( !pkg_op_match(op:op1, n:n) ) return 0;

 # All versions > X vulnerables ? I don't think so
 if ( op2 == 0 && ( op1 == OPERATOR_GT || op1 == OPERATOR_GTE ) ) return 0;


 if ( op2 != 0 )
 {
 n = pkg_cmp(pkg:package, reference:pkg_name + "-" + op2_arg);
 if ( !pkg_op_match(op:op2, n:n) ) return 0;
 }
 
 #display(ereg_replace(pattern:"^([^ ]*).*", string:package,replace:"\1"), " IS TOO OLD  - should be ",op1, " ", op1_arg, " ", op2, " ", op2_arg, "\n");

 report = "
Synopsis :

The remote host is missing a security update

Description :


The remote package " + ereg_replace(pattern:"^([^ ]*).*", string:package,replace:"\1") + " is not up-to-date.

Type of problem : " + problem + '


Solution :\n\n' + url + '\n';

 if ( strlen(seealso) > 1 ) report += "See also : " + seealso;

 report += '\n\nPlugin output :

' + package + ' is installed on the remote host.\n';

 if ( isnull(cvss_score) ) cvss_score = 10;
 if ( cvss_score >= 7 )
  security_hole(port:0, data:report);
 else if ( cvss_score >= 4 )
  security_warning(port:0, data:report);
 else
  security_note(port:0, data:report);
 return 1;
}
