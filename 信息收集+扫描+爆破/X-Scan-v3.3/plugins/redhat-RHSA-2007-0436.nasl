
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25479);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0436:   kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0436");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages are now available as part of ongoing support and
  maintenance of Red Hat Enterprise Linux version 3. This is the ninth
  regular update.

  This security advisory has been rated as having important security impact
  by the Red Hat Security Response Team.

  The Linux kernel handles the basic functions of the operating system.

  This is the ninth regular kernel update to Red Hat Enterprise Linux 3.

  There were no new features introduced by this update. The only changes
  that have been included address critical customer needs or security
  issues (elaborated below).

  Key areas affected by fixes in this update include the networking
  subsystem, dcache handling, the ext2 and ext3 file systems, the USB
  subsystem, ACPI handling, and the audit subsystem. There were also
  several isolated fixes in the tg3, e1000, megaraid_sas, and aacraid
  device drivers.

  The following security bugs were fixed in this update:

  * a flaw in the cramfs file system that allowed invalid compressed
  data to cause memory corruption (CVE-2006-5823, low)

  * a flaw in the ext2 file system that allowed an invalid inode size
  to cause a denial of service (system hang) (CVE-2006-6054, low)

  * a flaw in IPV6 flow label handling that allowed a local user to
  cause a denial of service (crash) (CVE-2007-1592, important)

  Note: The kernel-unsupported package contains various drivers and modules
  that are unsupported and therefore might contain security problems that
  have not been addressed.

  All Red Hat Enterprise Linux 3 users are advised to upgrade their
  kernels to the packages associated with their machine architectures
  and configurations as listed in this erratum.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0436.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-5823", "CVE-2006-6054", "CVE-2007-1592");
script_summary(english: "Check for the version of the   kernel packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"  kernel-2.4.21-50.EL.athlon.rpm                        7cfbe7d0110e0c1381b73177104119ec", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.21-50.EL", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.21-50.EL", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.21-50.EL", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.4.21-50.EL", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-unsupported-2.4.21-50.EL", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-2.4.21-50.EL.athlon.rpm                    1ceae1fcc0a9d53ee80ca959f077d1bf", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.21-50.EL", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-unsupported-2.4.21-50.EL.athlon.rpm        59b44b72919e9aa6ca57bd5eaafd686b", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-unsupported-2.4.21-50.EL", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-50.EL", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-unsupported-2.4.21-50.EL.athlon.rpm            1543ab5008587ee48e77f6ff55e3b69e", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-unsupported-2.4.21-50.EL", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
