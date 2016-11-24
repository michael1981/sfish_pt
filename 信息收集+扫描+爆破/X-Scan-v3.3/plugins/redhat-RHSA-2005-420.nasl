
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(18444);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-420: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-420");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages are now available as part of ongoing support
  and maintenance of Red Hat Enterprise Linux version 4. This is the
  first regular update.

  [Updated 9 August 2005]
  The advisory text has been updated to show that this update also contained
  fixes for the security issues named CAN-2005-0209 and CAN-2005-0937. No
  changes have been made to the packages associated with this advisory.

  The Linux kernel handles the basic functions of the operating system.

  This is the first regular kernel update to Red Hat Enterprise Linux 4.

  A flaw affecting the auditing code was discovered. On Itanium
  architectures a local user could use this flaw to cause a denial of service
  (crash). This issue is rated as having important security impact
  (CAN-2005-0136).

  A flaw was discovered in the servicing of a raw device ioctl. A local user
  who has access to raw devices could use this flaw to write to kernel memory
  and cause a denial of service or potentially gain privileges. This issue
  is rated as having moderate security impact (CAN-2005-1264).

  A flaw in fragment forwarding was discovered that affected the netfilter
  subsystem for certain network interface cards. A remote attacker could send
  a set of bad fragments and cause a denial of service (system crash). Acenic
  and SunGEM network interfaces were the only adapters affected, which are in
  widespread use. (CAN-2005-0209)

  A flaw in the futex functions was discovered affecting the Linux 2.6
  kernel. A local user could use this flaw to cause a denial of service
  (system crash). (CAN-2005-0937)

  New features introduced by this update include:
  - Fixed TCP BIC congestion handling.
  - Diskdump support for more controllers (megaraid, SATA)
  - Device mapper multipath support
  - AMD64 dual core support.
  - Intel ICH7 hardware support.

  There were many bug fixes in various parts of the kernel. The ongoing
  effort to resolve these problems has resulted in a marked improvement
  in the reliability and scalability of Red Hat Enterprise Linux 4.

  The following device drivers have been upgraded to new versions:
  ata_piix -------- 1.03
  bonding --------- 2.6.1
  e1000 ----------- 5.6.10.1-k2-NAPI
  e100 ------------ 3.3.6-k2-NAPI
  ibmveth --------- 1.03
  libata ---------- 1.02 to 1.10
  lpfc ------------ 0:8.0.16 to 0:8.0.16.6_x2
  megaraid_mbox --- 2.20.4.0 to 2.20.4.5
  megaraid_mm ----- 2.20.2.0-rh1 to 2.20.2.5
  sata_nv --------- 0.03 to 0.6
  sata_promise ---- 1.00 to 1.01
  sata_sil -------- 0.8
  sata_sis -------- 0.5
  sata_svw -------- 1.05
  sata_sx4 -------- 0.7
  sata_via -------- 1.0
  sata_vsc -------- 1.0
  tg3 ------------- 3.22-rh
  ipw2100 --------- 1.0.3
  ipw2200 --------- 1.0.0

  All Red Hat Enterprise Linux 4 users are advised to upgrade their
  kernels to the packages associated with their machine architectures
  and configurations as listed in this erratum.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-420.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-0136", "CVE-2005-0209", "CVE-2005-0937", "CVE-2005-1264", "CVE-2005-3107");
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

if ( rpm_check( reference:"kernel-2.6.9-11.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.9-11.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.9-11.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.6.9-11.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-devel-2.6.9-11.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.9-11.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-devel-2.6.9-11.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
