
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25137);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0220: cpp");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0220");
 script_set_attribute(attribute: "description", value: '
  Updated gcc packages that fix a security issue and various bugs are now
  available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The gcc packages include C, C++, Java, Fortran 77, Objective C, and Ada 95
  GNU compilers and related support libraries.

  J  rgen Weigert discovered a directory traversal flaw in fastjar. An
  attacker could create a malicious JAR file which, if unpacked using
  fastjar, could write to any files the victim had write access to.
  (CVE-2006-3619)

  These updated packages also fix several bugs, including:

  * two debug information generator bugs

  * two internal compiler errors

  In addition to this, protoize.1 and unprotoize.1 manual pages have been
  added to the package and __cxa_get_exception_ptr@@CXXABI_1.3.1 symbol has
  been added into libstdc++.so.6.

  For full details regarding all fixed bugs, refer to the package changelog
  as well as the specified list of bug reports from bugzilla.

  All users of gcc should upgrade to these updated packages, which contain
  backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0220.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-3619");
script_summary(english: "Check for the version of the cpp packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"cpp-3.4.6-8", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gcc-3.4.6-8", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gcc-c++-3.4.6-8", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gcc-g77-3.4.6-8", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gcc-gnat-3.4.6-8", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gcc-java-3.4.6-8", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gcc-objc-3.4.6-8", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libf2c-3.4.6-8", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgcc-3.4.6-8", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgcj-3.4.6-8", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgcj-devel-3.4.6-8", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgnat-3.4.6-8", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libobjc-3.4.6-8", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libstdc++-3.4.6-8", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libstdc++-devel-3.4.6-8", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
