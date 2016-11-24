#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(19290);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2005-0448");
 
 name["english"] = "Fedora Core 3 2005-600: perl";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2005-600 (perl).

Perl is a high-level programming language with roots in C, sed, awk
and shell scripting. Perl is good at handling processes and files,
and is especially good at handling text. Perl's hallmarks are
practicality and efficiency. While it is used to do a lot of
different things, Perl's most common applications are system
administration utilities and web programming. A large proportion of
the CGI scripts on the web are written in Perl. You need the perl
package installed on your system so that your system can handle Perl
scripts.

Install this package if you want to program in Perl or enable your
system to handle Perl scripts.

Update Information:

Paul Szabo discovered another vulnerability in the File::Path::rmtree
function
of perl, the popular scripting language. When a process is deleting a
directory
tree, a different user could exploit a race condition to create setuid
binaries in
this directory tree, provided that he already had write permissions in
any
subdirectory of that tree.

Perl interpreter would cause a segmentation fault when environment
changes
during the runtime.

Code in lib/FindBin contained a regression which caused problems with
MRTG
software package.

All of the above problems are now fixed in perl-5.8.5-14.FC3. Please
test as much
as you can and report any problems/regressions." );
 script_set_attribute(attribute:"solution", value:
"http://www.fedoranews.org/blog/index.php?p=786" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the perl package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"perl-5.8.5-14.FC3", release:"FC3") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-suidperl-5.8.5-14.FC3", release:"FC3") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-debuginfo-5.8.5-14.FC3", release:"FC3") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_exists(rpm:"perl-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-0448", value:TRUE);
}
