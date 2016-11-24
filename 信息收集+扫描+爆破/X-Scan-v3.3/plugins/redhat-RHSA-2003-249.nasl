
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12414);
 script_version ("$Revision: 1.8 $");
 script_name(english: "RHSA-2003-249: glibc");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-249");
 script_set_attribute(attribute: "description", value: '
  Updated glibc packages that fix a number of bugs as well as a buffer
  overflow issue are now available.

  The GNU libc package (known as glibc) contains the standard C libraries
  used by applications.

  A bug in the getgrouplist function can cause a buffer overflow if
  the size of the group list is too small to hold all the user\'s groups.
  This overflow can cause segmentation faults in user applications, which may
  have security implications, depending on the application in question. This
  vulnerability exists only when an administrator has placed a user in a
  number of groups larger than that expected by an application. Therefore,
  there is no risk in instances where users are members of few groups. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CAN-2003-0689 to this issue.

  In addition, a number of other bugs in glibc have been fixed:

  - An error prevented gdb from correctly debugging programs linked to
  libpthread.

  - A race condition existed in the malloc routine for IA64 platforms, which
  could cause memory corruption.

  - An error in pthread_spinlocks prevents spinlocks from functioning
  correctly on IA64 platforms.

  All users should upgrade to these errata packages, which contain patches to
  the glibc libraries correcting these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-249.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0689");
script_summary(english: "Check for the version of the glibc packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"glibc-2.2.4-32.8", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"glibc-common-2.2.4-32.8", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"glibc-devel-2.2.4-32.8", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"glibc-profile-2.2.4-32.8", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nscd-2.2.4-32.8", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
