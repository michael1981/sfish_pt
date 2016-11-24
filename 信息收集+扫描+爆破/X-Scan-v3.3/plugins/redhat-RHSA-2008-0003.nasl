
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29876);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2008-0003: e");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0003");
 script_set_attribute(attribute: "description", value: '
  Updated e2fsprogs packages that fix several security issues are now
  available for Red Hat Enterprise Linux.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The e2fsprogs packages contain a number of utilities for creating,
  checking, modifying, and correcting any inconsistencies in second and third
  extended (ext2/ext3) file systems.

  Multiple integer overflow flaws were found in the way e2fsprogs processes
  file system content. If a victim opens a carefully crafted file system with
  a program using e2fsprogs, it may be possible to execute arbitrary code
  with the permissions of the victim. It may be possible to leverage this
  flaw in a virtualized environment to gain access to other virtualized
  hosts. (CVE-2007-5497)

  Red Hat would like to thank Rafal Wojtczuk of McAfee Avert Research for
  responsibly disclosing these issues.

  Users of e2fsprogs are advised to upgrade to these updated packages, which
  contain a backported patch to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0003.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-5497");
script_summary(english: "Check for the version of the e packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"e2fsprogs-1.39-10.el5_1.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"e2fsprogs-devel-1.39-10.el5_1.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"e2fsprogs-libs-1.39-10.el5_1.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"e2fsprogs-1.26-1.73", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"e2fsprogs-devel-1.26-1.73", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"e2fsprogs-1.32-15.4", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"e2fsprogs-devel-1.32-15.4", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"e2fsprogs-1.35-12.11.el4_6.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"e2fsprogs-devel-1.35-12.11.el4_6.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
