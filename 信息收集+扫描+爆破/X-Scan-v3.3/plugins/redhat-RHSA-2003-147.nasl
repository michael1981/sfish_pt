
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12390);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2003-147:   kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-147");
 script_set_attribute(attribute: "description", value: '
  These updated kernel packages address security vulnerabilites, including
  two possible data corruption scenarios. In addition, a number of
  drivers have been updated, improvements made to system performance, and
  various issues have been resolved.

  The Linux kernel handles the basic functions of the operating system.

  Two potential data corruption scenarios have been identified. These
  scenarios can occur under heavy, complex I/O loads.

  The first scenario only occurs while performing memory mapped file I/O,
  where the file is simultaneously unlinked and the corresponding file blocks
  reallocated. Furthermore, the memory mapped must be to a partial page at
  the end of a file on an ext3 file system. As such, Red Hat considers this
  scenario unlikely.

  The second scenario was exhibited in systems with more than 4 GB of memory
  with a storage controller capable of block device DMA above 4GB (64-bit
  DMA). By restricting storage drivers to 32-bit DMA, the problem was
  resolved. Prior to this errata, the SCSI subsystem was already restricted
  to 32-bit DMA; this errata extends the restriction to block drivers as
  well. The change consists of disabling 64-bit DMA in the cciss driver
  (the HP SA5xxx and SA6xxx RAID controllers). The performance implications
  of this change to the cciss driver are minimal.

  In addition, the following security vulnerabilities have been addressed:

  A flaw was found in several hash table implementations in the kernel
  networking code. A remote attacker sending packets with carefully
  chosen, forged source addresses could potentially cause every routing
  cache entry to be hashed into the same hash chain. As a result, the kernel
  would use a disproportionate amount of processor time to deal
  with the new packets, leading to a remote denial-of-service (DoS) attack.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CAN-2003-0244 to this issue.

  A flaw was also found in the "ioperm" system call, which fails to properly
  restrict privileges. This flaw can allow an unprivileged local user to gain
  read and write access to I/O ports on the system. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2003-0246 to this issue.

  In addition, the following drivers have been updated to the versions
  indicated:

  -aacraid: 0.9.9ac6-TEST
  -qlogic qla2100, qla2200, qla2300: 6.04.01
  -aic7xxx_mod: 6.2.30 and aic79xx: 1.3.4
  -ips: v6.00.26
  -cpqfc: 2.1.2
  -fusion: 2.05.00
  -e100: 2.2.21-k1
  -e1000: 5.0.43-k1, and added netdump support
  -natsemi: 1.07+LK1.0.17
  -cciss: 2.4.45.
  -cpqarray: 2.4.26

  If the system is configured to use alternate drivers, we recommend applying
  the kudzu errata RHEA-2003:132 prior to updating the kernel.

  A number of edge conditions in the virtual memory system have been
  identified and resolved. These included the elimination of memory
  allocation failures occuring when the system had not depleted all of the
  physical memory. This would typically lead to process creation and network
  driver failures, and general performance degradation. Additional memory
  reclamation improvements were introduced to further smooth out the natural
  system performance degradation that occur under memory exhaustion
  conditions.

  In addition, the latest summit patches have been included.

  All users should upgrade to these errata packages, which address these
  issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-147.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0244", "CVE-2003-0246");
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

if ( rpm_check( reference:"  kernel-2.4.9-e.24.athlon.rpm               b905af879082ab03a87a733d0de29665", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.9-e.24", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.9-e.24", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.4.9-e.24", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.9-e.24", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.4.9-e.24", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.4.9-e.24", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-2.4.9-e.24.athlon.rpm           50b706126d20493d697a37bf2af9c4a4", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.9-e.24", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.9-e.24", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-summit-2.4.9-e.24", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
