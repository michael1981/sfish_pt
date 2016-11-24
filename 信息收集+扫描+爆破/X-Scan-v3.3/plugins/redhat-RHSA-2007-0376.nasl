
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25538);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0376: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0376");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix security issues and bugs in the Red Hat
  Enterprise Linux 5 kernel are now available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The Linux kernel handles the basic functions of the operating system.

  These new kernel packages contain fixes for the following security issues:

  * a flaw in the mount handling routine for 64-bit systems that allowed a
  local user to cause denial of service (CVE-2006-7203, Important).

  * a flaw in the PPP over Ethernet implementation that allowed a remote user
  to cause a denial of service (CVE-2007-2525, Important).

  * a flaw in the Bluetooth subsystem that allowed a local user to trigger an
  information leak (CVE-2007-1353, Low).

  * a bug in the random number generator that prevented the manual seeding of
  the entropy pool (CVE-2007-2453, Low).

  In addition to the security issues described above, fixes for the following
  have been included:

  * a race condition between ext3_link/unlink that could create an orphan
  inode list corruption.

  * a bug in the e1000 driver that could lead to a watchdog timeout panic.

  Red Hat Enterprise Linux 5 users are advised to upgrade to these packages,
  which contain backported patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0376.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-7203", "CVE-2007-1353", "CVE-2007-2453", "CVE-2007-2525");
script_summary(english: "Check for the version of the kernel packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"kernel-2.6.18-8.1.6.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-2.6.18-8.1.6.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-devel-2.6.18-8.1.6.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.18-8.1.6.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.18-8.1.6.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.6.18-8.1.6.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.18-8.1.6.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-devel-2.6.18-8.1.6.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
