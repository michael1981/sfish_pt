
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(28363);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2007-0993: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0993");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix various security issues in the Red Hat
  Enterprise Linux 5 kernel are now available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The Linux kernel handles the basic functions of the operating system.

  These new kernel packages contain fixes for the following security issues:

  A memory leak was found in the Red Hat Content Accelerator kernel patch. A
  local user could use this flaw to cause a denial of service (memory
  exhaustion). (CVE-2007-5494, Important)

  A flaw was found in the handling of IEEE 802.11 frames affecting several
  wireless LAN modules. In certain circumstances, a remote attacker could
  trigger this flaw by sending a malicious packet over a wireless network and
  cause a denial of service (kernel crash). (CVE-2007-4997, Important).

  A flaw was found in the Advanced Linux Sound Architecture (ALSA). A local
  user who had the ability to read the /proc/driver/snd-page-alloc file could
  see portions of kernel memory. (CVE-2007-4571, Moderate).

  In addition to the security issues described above, several bug fixes
  preventing possible memory corruption, system crashes, SCSI I/O fails,
  networking drivers performance regression and journaling block device layer
  issue were also included.

  Red Hat Enterprise Linux 5 users are advised to upgrade to these packages,
  which contain backported patches to resolve these issues.

  Red Hat would like to credit Vasily Averin, Chris Evans, and Neil Kettle
  for reporting the security issues corrected by this update.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0993.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-4571", "CVE-2007-4997", "CVE-2007-5494");
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

if ( rpm_check( reference:"kernel-2.6.18-53.1.4.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-2.6.18-53.1.4.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-devel-2.6.18-53.1.4.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.18-53.1.4.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-devel-2.6.18-53.1.4.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.18-53.1.4.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.18-53.1.4.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.6.18-53.1.4.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.18-53.1.4.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-devel-2.6.18-53.1.4.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
