
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12306);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2002-128:   kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2002-128");
 script_set_attribute(attribute: "description", value: '
  This kernel update is available for Red Hat Linux Advanced Server 2.1.

  It includes a fix for an information security bug, various kernel bug
  fixes, and updated device drivers.

  [2002-07-29] This release is a rebuild for adding exported symbols for
  Veritas.

  This kernel fixes an information security bug. When running enterprise
  kernels previous to version 2.4.9-e.8, information in the Intel SSE XMM
  registers could "leak" between processes under certain circumstances.

  This update also includes fixes for the following bugs:

  - Creation of an Oracle SGA greater than 8 GB on 16 GB or greater machine
  when using bigpages and shmfs
  - Sendmail running out of flocks
  - Unreliable rebooting with the "reboot=bios" boot option
  - Potential memory corruption on systems with more than 4 GB
  - An AIO write deadlock
  - IOAPIC warnings on one platform
  - Potentially miscompiled code in xor.h (though kernel engineering
  research does not indicate that our compiler miscompiles this code)

  This kernel also has extra exported symbols removed.

  This new kernel also includes several updated device drivers. The
  aic7xxx_mod driver has been updated to a new version, fixing several
  bugs, the tg3 driver has also been updated to a new version to fix various
  bugs, and the qla2300 driver has some small bug fixes and has been updated
  to work with the QLogic 2340 HBA and PowerVault 660F arrays. Additions to
  the SCSI LUNs "white list" have also been made to support more fibre
  channel arrays.

  [2002-07-29] This new kernel is a rebuild for adding exported symbols for
  Veritas.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2002-128.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2002-1571");
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

if ( rpm_check( reference:"  kernel-2.4.9-e.8.athlon.rpm               e72519cb943f692dfff7601c3b3d8211", release:'RHEL2.1') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.9-e.8", release:'RHEL2.1') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.9-e.8", release:'RHEL2.1') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.4.9-e.8", release:'RHEL2.1') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.9-e.8", release:'RHEL2.1') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.4.9-e.8", release:'RHEL2.1') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.4.9-e.8", release:'RHEL2.1') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-2.4.9-e.8.athlon.rpm           7fb4cb89ea4100d4e41fbcd0ec7becb1", release:'RHEL2.1') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.9-e.8", release:'RHEL2.1') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.9-e.8", release:'RHEL2.1') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-summit-2.4.9-e.8", release:'RHEL2.1') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
