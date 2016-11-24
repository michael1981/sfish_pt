
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(18161);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2005-283:   kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-283");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages are now available as part of ongoing support and
  maintenance of Red Hat Enterprise Linux version 2.1. This is the seventh
  regular update.

  This security advisory has been rated as having important security impact
  by the Red Hat Security Response Team.

  The Linux kernel handles the basic functions of the operating system.

  This is the seventh regular kernel update to Red Hat Enterprise Linux 2.1

  The following security updates were made:

  A flaw in fragment queuing was discovered that affected the Linux 2.4 and
  Linux 2.6 kernel netfilter subsystem. On systems configured to filter or
  process network packets (for example those configured to do firewalling),
  a remote attacker could send a carefully crafted set of fragmented packets
  to a machine and cause a denial of service (system crash). In order to
  sucessfully exploit this flaw, the attacker would need to know (or guess)
  some aspects of the firewall ruleset in place on the target system to be
  able to craft the right fragmented packets. (CAN-2005-0449)

  A flaw was discovered in the Linux PPP driver. On systems allowing remote
  users to connect to a server using ppp, a remote client could cause a
  denial of service (system crash). (CAN-2005-0384)

  A flaw was discovered in the bluetooth driver system. On system where the
  bluetooth modules are loaded, a local user could use this flaw to gain
  elevated (root) privileges. (CAN-2005-0750)

  An integer overflow flaw was discovered in the ubsec_keysetup function
  in the Broadcom 5820 cryptonet driver. On systems using this driver,
  a local user could cause a denial of service (crash) or possibly gain
  elevated privileges. (CAN-2004-0619) Please note that this update contains
  an unpatched kernel module called bcm5820_old for backwards compatibility
  which is still vulnerable to CAN-2004-0619.

  The following device drivers have been updated to new versions:

  mptfusion: 2.05.16 -> 2.05.16.02
  bcm5820: 1.17 -> 1.81
  cciss: 2.4.52 -> 2.4.54
  qla2x00: 6.04.01 -> 7.01.01

  There were many bug fixes in various parts of the kernel. The ongoing
  effort to resolve these problems has resulted in a marked improvement
  in the reliability and scalability of Red Hat Enterprise Linux 2.1.

  Bug fixes include:
  - Fixes an incorrect and ever-changing physical_id field in
  /proc/cpuinfo.
  - Now recognizes a particular e1000 device (PCI ID 8086:1014)
  - Fixes a panic in disk quota code
  - Fixes a bug in which msync(...MS_SYNC) returns before the data
  is written to disk
  - Adds new devices to the SCSI scan list so they can
  be initialized and handled properly: LSI ProFibre 4000R, HP
  HSV200/210, HP MSA, STK OPENstorage D178.
  - Fixes a potential format overflow in /proc/partitions
  - Restores module parameters to the e100 driver for compatibility with
  existing customer scripts.
  - Fixes a bug in which cat\'ing /proc/mdstat while adding/removing
  devices can cause a kernel oops

  All Red Hat Enterprise Linux 2.1 users are advised to upgrade their
  kernels to the packages associated with their machine architectures
  and configurations as listed in this erratum.

  Please note that a vulnerability addressed by this update (CAN-2005-0449)
  required a change to the kernel module ABI which could cause third party
  modules to not work. However, Red Hat is currently not aware of any module
  that would be affected by this change.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-283.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0619", "CVE-2005-0384", "CVE-2005-0449", "CVE-2005-0750");
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

if ( rpm_check( reference:"  kernel-2.4.9-e.62.athlon.rpm               7fa5f91dac379821e1cb6413b5db02ff", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.9-e.62", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.9-e.62", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.4.9-e.62", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.9-e.62", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.4.9-e.62", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.4.9-e.62", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-2.4.9-e.62.athlon.rpm           2f129c38c477f62e934936f6db7a65ba", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.9-e.62", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.9-e.62", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-summit-2.4.9-e.62", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
