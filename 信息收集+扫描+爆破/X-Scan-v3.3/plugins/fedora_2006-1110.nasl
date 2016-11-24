
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2006-1110
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24039);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 5 2006-1110: ruby");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2006-1110 (ruby)");
 script_set_attribute(attribute: "description", value: "Ruby is the interpreted scripting language for quick and easy
object-oriented programming.  It has many features to process text
files and to do system management tasks (as in Perl).  It is simple,
straight-forward, and extensible.



Update information :

* Fri Oct 27 2006 Akira TAGOH <tagoh redhat com> - 1.8.5-1
- security fix release.
- ruby-1.8.5-cgi-CVE-2006-5467.patch: fix a CGI multipart parsing bug that
causes the denial of service. (#212396)
- backport fixes from devel.
- fixed rbconfig.rb to refer to DESTDIR for sitearchdir. (#207311)
- updates to 1.8.5
- removed the unnecessary patches:
ruby-1.8.4-no-eaccess.patch, ruby-1.8.4-64bit-pack.patch,
ruby-1.8.4-fix-insecure-dir-operation.patch,
ruby-1.8.4-fix-insecure-regexp-modification.patch,
ruby-1.8.4-fix-alias-safe-level.patch.
- build with --enable-pthread except on ppc.
- ruby-1.8.5-hash-memory-leak.patch: backported from CVS to fix a memory leak
on Hash. [ruby-talk:211233]
- owns sitearchdir. (#201208)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2006-3694", "CVE-2006-5467");
script_summary(english: "Check for the version of the ruby package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"ruby-irb-1.8.5-1.fc5", release:"FC5") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-libs-1.8.5-1.fc5", release:"FC5") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-mode-1.8.5-1.fc5", release:"FC5") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-docs-1.8.5-1.fc5", release:"FC5") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-1.8.5-1.fc5", release:"FC5") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-tcltk-1.8.5-1.fc5", release:"FC5") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-ri-1.8.5-1.fc5", release:"FC5") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-devel-1.8.5-1.fc5", release:"FC5") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-rdoc-1.8.5-1.fc5", release:"FC5") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
