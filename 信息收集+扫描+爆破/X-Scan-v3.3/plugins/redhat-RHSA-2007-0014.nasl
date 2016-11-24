
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(24315);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0014: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0014");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix several security issues in the Red Hat
  Enterprise Linux 4 kernel are now available.

  This security advisory has been rated as having important security impact
  by the Red Hat Security Response Team.

  The Linux kernel handles the basic functions of the operating system.

  These new kernel packages contain fixes for the security issues described
  below:

  * a flaw in the get_fdb_entries function of the network bridging support
  that allowed a local user to cause a denial of service (crash) or allow a
  potential privilege escalation (CVE-2006-5751, Important)

  * an information leak in the _block_prepare_write function that allowed a
  local user to read kernel memory (CVE-2006-4813, Important)

  * an information leak in the copy_from_user() implementation on s390 and
  s390x platforms that allowed a local user to read kernel memory
  (CVE-2006-5174, Important)

  * a flaw in the handling of /proc/net/ip6_flowlabel that allowed a local
  user to cause a denial of service (infinite loop) (CVE-2006-5619, Important)

  * a flaw in the AIO handling that allowed a local user to cause a denial of
  service (panic) (CVE-2006-5754, Important)

  * a race condition in the mincore system core that allowed a local user to
  cause a denial of service (system hang) (CVE-2006-4814, Moderate)

  * a flaw in the ELF handling on ia64 and sparc architectures which
  triggered a cross-region memory mapping and allowed a local user to cause a
  denial of service (CVE-2006-4538, Moderate)

  * a flaw in the dev_queue_xmit function of the network subsystem that
  allowed a local user to cause a denial of service (data corruption)
  (CVE-2006-6535, Moderate)

  * a flaw in the handling of CAPI messages over Bluetooth that allowed a
  remote system to cause a denial of service or potential code execution.
  This flaw is only exploitable if a privileged user establishes a connection
  to a malicious remote device (CVE-2006-6106, Moderate)

  * a flaw in the listxattr system call that allowed a local user to cause a
  denial of service (data corruption) or potential privilege escalation. To
  successfully exploit this flaw the existence of a bad inode is required
  first (CVE-2006-5753, Moderate)

  * a flaw in the __find_get_block_slow function that allowed a local
  privileged user to cause a denial of service (CVE-2006-5757, Low)

  * various flaws in the supported filesystems that allowed a local
  privileged user to cause a denial of service (CVE-2006-5823, CVE-2006-6053,
  CVE-2006-6054, CVE-2006-6056, Low)

  In addition to the security issues described above, fixes for the following
  bugs were included:

  * initialization error of the tg3 driver with some BCM5703x network card

  * a memory leak in the audit subsystem

  * x86_64 nmi watchdog timeout is too short

  * ext2/3 directory reads fail intermittently

  Red Hat would like to thank Dmitriy Monakhov and Kostantin Khorenko for
  reporting issues fixed in this erratum.

  All Red Hat Enterprise Linux 4 users are advised to upgrade their kernels
  to the packages associated with their machine architecture and
  configurations as listed in this erratum.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0014.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-4538", "CVE-2006-4813", "CVE-2006-4814", "CVE-2006-5174", "CVE-2006-5619", "CVE-2006-5751", "CVE-2006-5753", "CVE-2006-5754", "CVE-2006-5757", "CVE-2006-5823", "CVE-2006-6053", "CVE-2006-6054", "CVE-2006-6056", "CVE-2006-6106", "CVE-2006-6535");
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

if ( rpm_check( reference:"kernel-2.6.9-42.0.8.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.9-42.0.8.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.9-42.0.8.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.6.9-42.0.8.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-devel-2.6.9-42.0.8.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.9-42.0.8.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-devel-2.6.9-42.0.8.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
