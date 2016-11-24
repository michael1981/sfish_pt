
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27616);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0939: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0939");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix various security issues in the Red Hat
  Enterprise Linux 4 kernel are now available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The Linux kernel is the core of the operating system.

  These updated kernel packages contain fixes for the following security
  issues:

  * A flaw was found in the handling of process death signals. This allowed a
  local user to send arbitrary signals to the suid-process executed by that
  user. A successful exploitation of this flaw depends on the structure of
  the suid-program and its signal handling. (CVE-2007-3848, Important)

  * A flaw was found in the CIFS file system. This could cause the umask
  values of a process to not be honored on CIFS file systems where UNIX
  extensions are supported. (CVE-2007-3740, Important)

  * A flaw was found in the VFAT compat ioctl handling on 64-bit systems.
  This allowed a local user to corrupt a kernel_dirent struct and cause a
  denial of service. (CVE-2007-2878, Important)

  * A flaw was found in the Advanced Linux Sound Architecture (ALSA). A local
  user who had the ability to read the /proc/driver/snd-page-alloc file could
  see portions of kernel memory. (CVE-2007-4571, Moderate)

  * A flaw was found in the aacraid SCSI driver. This allowed a local user to
  make ioctl calls to the driver that should be restricted to privileged
  users. (CVE-2007-4308, Moderate)

  * A flaw was found in the stack expansion when using the hugetlb kernel on
  PowerPC systems. This allowed a local user to cause a denial of service.
  (CVE-2007-3739, Moderate)

  * A flaw was found in the handling of zombie processes. A local user could
  create processes that would not be properly reaped which could lead to a
  denial of service. (CVE-2006-6921, Moderate)

  * A flaw was found in the CIFS file system handling. The mount option
  "sec=" did not enable integrity checking or produce an error message if
  used. (CVE-2007-3843, Low)

  * A flaw was found in the random number generator implementation that
  allowed a local user to cause a denial of service or possibly gain
  privileges. This flaw could be exploited if the root user raised the
  default wakeup threshold over the size of the output pool.
  (CVE-2007-3105, Low)

  Additionally, the following bugs were fixed:

  * A flaw was found in the kernel netpoll code, creating a potential
  deadlock condition. If the xmit_lock for a given network interface is
  held, and a subsequent netpoll event is generated from within the lock
  owning context (a console message for example), deadlock on that cpu will
  result, because the netpoll code will attempt to re-acquire the xmit_lock.
  The fix is to, in the netpoll code, only attempt to take the lock, and
  fail if it is already acquired (rather than block on it), and queue the
  message to be sent for later delivery. Any user of netpoll code in the
  kernel (netdump or netconsole services), is exposed to this problem, and
  should resolve the issue by upgrading to this kernel release immediately.

  * A flaw was found where, under 64-bit mode (x86_64), AMD processors were
  not able to address greater than a 40-bit physical address space; and Intel
  processors were only able to address up to a 36-bit physical address space.
  The fix is to increase the physical addressing for an AMD processor to 48
  bits, and an Intel processor to 38 bits. Please see the Red Hat
  Knowledgebase for more detailed information.

  * A flaw was found in the xenU kernel that may prevent a paravirtualized
  guest with more than one CPU from starting when running under an Enterprise
  Linux 5.1 hypervisor. The fix is to allow your Enterprise Linux 4 Xen SMP
  guests to boot under a 5.1 hypervisor. Please see the Red Hat Knowledgebase
  for more detailed information.

  Red Hat Enterprise Linux 4 users are advised to upgrade to these updated
  packages, which contain backported patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0939.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-6921", "CVE-2007-2878", "CVE-2007-3105", "CVE-2007-3739", "CVE-2007-3740", "CVE-2007-3843", "CVE-2007-3848", "CVE-2007-4308", "CVE-2007-4571");
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

if ( rpm_check( reference:"kernel-2.6.9-55.0.12.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.9-55.0.12.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.9-55.0.12.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.6.9-55.0.12.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-devel-2.6.9-55.0.12.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.9-55.0.12.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-devel-2.6.9-55.0.12.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.9-55.0.12.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-devel-2.6.9-55.0.12.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
