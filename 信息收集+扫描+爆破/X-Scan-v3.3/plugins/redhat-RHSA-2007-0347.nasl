
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25333);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0347: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0347");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix security issues and bugs in the Red Hat
  Enterprise Linux 5 kernel are now available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The Linux kernel handles the basic functions of the operating system.

  These new kernel packages contain fixes for the following security issues:

  * a flaw in the handling of IPv6 type 0 routing headers that allowed remote
  users to cause a denial of service that led to a network amplification
  between two routers (CVE-2007-2242, Important).

  * a flaw in the nfnetlink_log netfilter module that allowed a local user to
  cause a denial of service (CVE-2007-1496, Important).

  * a flaw in the flow list of listening IPv6 sockets that allowed a local
  user to cause a denial of service (CVE-2007-1592, Important).

  * a flaw in the handling of netlink messages that allowed a local user to
  cause a denial of service (infinite recursion) (CVE-2007-1861, Important).

  * a flaw in the IPv4 forwarding base that allowed a local user to cause an
  out-of-bounds access (CVE-2007-2172, Important).

  * a flaw in the nf_conntrack netfilter module for IPv6 that allowed remote
  users to bypass certain netfilter rules using IPv6 fragments
  (CVE-2007-1497, Moderate).

  In addition to the security issues described above, fixes for the following
  have been included:

  * a regression in ipv6 routing.

  * an error in memory initialization that caused gdb to output inaccurate
  backtraces on ia64.

  * the nmi watchdog timeout was updated from 5 to 30 seconds.

  * a flaw in distributed lock management that could result in errors during
  virtual machine migration.

  * an omitted include in kernel-headers that led to compile failures for
  some packages.

  Red Hat Enterprise Linux 5 users are advised to upgrade to these packages,
  which contain backported patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0347.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-1496", "CVE-2007-1497", "CVE-2007-1592", "CVE-2007-1861", "CVE-2007-2172", "CVE-2007-2242");
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

if ( rpm_check( reference:"kernel-2.6.18-8.1.4.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-2.6.18-8.1.4.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-devel-2.6.18-8.1.4.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.18-8.1.4.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.18-8.1.4.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.6.18-8.1.4.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.18-8.1.4.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-devel-2.6.18-8.1.4.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
