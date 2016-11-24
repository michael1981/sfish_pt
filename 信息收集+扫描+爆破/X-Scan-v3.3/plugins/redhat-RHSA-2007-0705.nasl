
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(26050);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0705: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0705");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix various security issues in the Red Hat
  Enterprise Linux 5 kernel are now available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The Linux kernel handles the basic functions of the operating system.

  These new kernel packages contain fixes for the following security issues:

  * a flaw in the DRM driver for Intel graphics cards that allowed a local
  user to access any part of the main memory. To access the DRM functionality
  a user must have access to the X server which is granted through the
  graphical login. This also only affected systems with an Intel 965 or later
  graphic chipset. (CVE-2007-3851, Important)

  * a flaw in the VFAT compat ioctl handling on 64-bit systems that allowed a
  local user to corrupt a kernel_dirent struct and cause a denial of service
  (system crash). (CVE-2007-2878, Important)

  * a flaw in the connection tracking support for SCTP that allowed a remote
  user to cause a denial of service by dereferencing a NULL pointer.
  (CVE-2007-2876, Important)

  * flaw in the CIFS filesystem which could cause the umask values of a
  process to not be honored. This affected CIFS filesystems where the Unix
  extensions are supported. (CVE-2007-3740, Important)

  * a flaw in the stack expansion when using the hugetlb kernel on PowerPC
  systems that allowed a local user to cause a denial of service.
  (CVE-2007-3739, Moderate)

  * a flaw in the ISDN CAPI subsystem that allowed a remote user to cause a
  denial of service or potential remote access. Exploitation would require
  the attacker to be able to send arbitrary frames over the ISDN network to
  the victim\'s machine. (CVE-2007-1217, Moderate)

  * a flaw in the cpuset support that allowed a local user to obtain
  sensitive information from kernel memory. To exploit this the cpuset
  filesystem would have to already be mounted. (CVE-2007-2875, Moderate)

  * a flaw in the CIFS handling of the mount option "sec=" that didn\'t enable
  integrity checking and didn\'t produce any error message. (CVE-2007-3843,
  Low)

  Red Hat Enterprise Linux 5 users are advised to upgrade to these packages,
  which contain backported patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0705.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-1217", "CVE-2007-2875", "CVE-2007-2876", "CVE-2007-2878", "CVE-2007-3739", "CVE-2007-3740", "CVE-2007-3843", "CVE-2007-3851");
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

if ( rpm_check( reference:"kernel-2.6.18-8.1.10.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-2.6.18-8.1.10.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-devel-2.6.18-8.1.10.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.18-8.1.10.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.18-8.1.10.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.6.18-8.1.10.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.18-8.1.10.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-devel-2.6.18-8.1.10.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
