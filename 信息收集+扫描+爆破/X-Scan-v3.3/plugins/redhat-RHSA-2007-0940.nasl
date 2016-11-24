
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27565);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2007-0940: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0940");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix various security issues in the Red Hat
  Enterprise Linux 5 kernel are now available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The Linux kernel handles the basic functions of the operating system.

  These new kernel packages contain fixes for the following security issues:

  * A flaw was found in the backported stack unwinder fixes in Red Hat
  Enterprise Linux 5. On AMD64 and Intel 64 platforms, a local user could
  trigger this flaw and cause a denial of service. (CVE-2007-4574, Important)

  * A flaw was found in the handling of process death signals. This allowed a
  local user to send arbitrary signals to the suid-process executed by that
  user. A successful exploitation of this flaw depends on the structure of
  the suid-program and its signal handling. (CVE-2007-3848, Important)

  * A flaw was found in the Distributed Lock Manager (DLM) in the cluster
  manager. This allowed a remote user who is able to connect to the DLM port
  to cause a denial of service. (CVE-2007-3380, Important)

  * A flaw was found in the aacraid SCSI driver. This allowed a local user to
  make ioctl calls to the driver which should otherwise be restricted to
  privileged users. (CVE-2007-4308, Moderate)

  * A flaw was found in the prio_tree handling of the hugetlb support that
  allowed a local user to cause a denial of service. This only affected
  kernels with hugetlb support. (CVE-2007-4133, Moderate)

  * A flaw was found in the eHCA driver on PowerPC architectures that allowed
  a local user to access 60k of physical address space. This address space
  could contain sensitive information. (CVE-2007-3850, Moderate)

  * A flaw was found in ptrace support that allowed a local user to cause a
  denial of service via a NULL pointer dereference. (CVE-2007-3731, Moderate)

  * A flaw was found in the usblcd driver that allowed a local user to cause
  a denial
  of service by writing data to the device node. To exploit this issue, write
  access to the device node was needed. (CVE-2007-3513, Moderate)

  * A flaw was found in the random number generator implementation that
  allowed a local user to cause a denial of service or possibly gain
  privileges. If the root user raised the default wakeup threshold over the
  size of the output pool, this flaw could be exploited. (CVE-2007-3105, Low)

  In addition to the security issues described above, several bug fixes
  preventing possible system crashes and data corruption were also included.

  Red Hat Enterprise Linux 5 users are advised to upgrade to these packages,
  which contain backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0940.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-3105", "CVE-2007-3380", "CVE-2007-3513", "CVE-2007-3731", "CVE-2007-3848", "CVE-2007-3850", "CVE-2007-4133", "CVE-2007-4308", "CVE-2007-4574");
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

if ( rpm_check( reference:"kernel-2.6.18-8.1.15.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-2.6.18-8.1.15.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-devel-2.6.18-8.1.15.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.18-8.1.15.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.18-8.1.15.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.6.18-8.1.15.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.18-8.1.15.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-devel-2.6.18-8.1.15.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
