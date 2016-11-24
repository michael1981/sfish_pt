
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33581);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2008-0665: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0665");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages are now available as part of ongoing support and
  maintenance of Red Hat Enterprise Linux 4. This is the seventh regular
  update.

  This update has been rated as having moderate security impact by the Red Hat
  Security Response Team.

  The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  Kernel Feature Support:
  * iostat displays I/O performance for partitions
  * I/O task accounting added to getrusage(), allowing comprehensive core
  statistics
  * page cache pages count added to show_mem() output
  * tux O_ATOMICLOOKUP flag removed from the open() system call: replaced
  with O_CLOEXEC
  * the kernel now exports process limit information to /proc/[PID]/limits
  * implement udp_poll() to reduce likelihood of false positives returned
  from select()
  * the TCP_RTO_MIN parameter can now be configured to a maximum of 3000
  milliseconds. This is configured using "ip route"
  * update CIFS to version 1.50

  Added Features:
  * nfs.enable_ino64 boot command line parameter: enable and disable 32-bit
  inode numbers when using NFS
  * tick "divider" kernel boot parameter: reduce CPU overhead, and increase
  efficiency at the cost of lowering timing accuracy
  * /proc/sys/vm/nfs-writeback-lowmem-only tunable parameter: resolve NFS
  read performance
  * /proc/sys/vm/write-mapped tunable option, allowing the option of faster
  NFS reads
  * support for Large Receive Offload as a networking module
  * core dump masking, allowing a core dump process to skip the shared memory
  segments of a process

  Virtualization:
  * para-virtualized network and block device drivers, to increase
  fully-virtualized guest performance
  * support for more than three VNIF numbers per guest domain

  Platform Support:
  * AMD ATI SB800 SATA controller, AMD ATI SB600 and SB700 40-pin IDE cable
  * 64-bit DMA support on AMD ATI SB700
  * PCI device IDs to support Intel ICH10
  * /dev/msr[0-n] device files
  * powernow-k8 as a module
  * SLB shadow buffer support for IBM POWER6 systems
  * support for CPU frequencies greater than 32-bit on IBM POWER5, IBM POWER6
  * floating point load and store handler for IBM POWER6

  Added Drivers and Updates:
  * ixgbe 1.1.18, for the Intel 82598 10GB ethernet controller
  * bnx2x 1.40.22, for network adapters on the Broadcom 5710 chipset
  * dm-hp-sw 1.0.0, for HP Active/Standby
  * zfcp version and bug fixes
  * qdio to fix FCP/SCSI write I/O expiring on LPARs
  * cio bug fixes
  * eHEA latest upstream, and netdump and netconsole support
  * ipr driver support for dual SAS RAID controllers
  * correct CPU cache info and SATA support for Intel Tolapai
  * i5000_edac support for Intel 5000 chipsets
  * i3000_edac support for Intel 3000 and 3010 chipsets
  * add i2c_piix4 module on 64-bit systems to support AMD ATI SB600, 700
  and 800
  * i2c-i801 support for Intel Tolapai
  * qla4xxx: 5.01.01-d2 to 5.01.02-d4-rhel4.7-00
  * qla2xxx: 8.01.07-d4 to 8.01.07-d4-rhel4.7-02
  * cciss: 2.6.16 to 2.6.20
  * mptfusion: 3.02.99.00rh to 3.12.19.00rh
  * lpfc:0: 8.0.16.34 to 8.0.16.40
  * megaraid_sas: 00.00.03.13 to 00.00.03.18-rh1
  * stex: 3.0.0.1 to 3.6.0101.2
  * arcmsr: 1.20.00.13 to 1.20.00.15.rh4u7
  * aacraid: 1.1-5[2441] to 1.1.5[2455]

  Miscellaneous Updates:
  * OFED 1.3 support
  * wacom driver to add support for Cintiq 20WSX, Wacom Intuos3 12x19, 12x12
  and 4x6 tablets
  * sata_svw driver to support Broadcom HT-1100 chipsets
  * libata to un-blacklist Hitachi drives to enable NCQ
  * ide driver allows command line option to disable ide drivers
  * psmouse support for cortps protocol

  These updated packages fix the following security issues:

  * NULL pointer access due to missing checks for terminal validity.
  (CVE-2008-2812, Moderate)

  * a security flaw was found in the Linux kernel Universal Disk Format file
  system. (CVE-2006-4145, Low)

  For further details, refer to the latest Red Hat Enterprise Linux 4.7
  release notes: redhat.com/docs/manuals/enterprise


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0665.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-4145", "CVE-2008-2812");
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

if ( rpm_check( reference:"kernel-2.6.9-78.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.9-78.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.9-78.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.6.9-78.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-devel-2.6.9-78.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.9-78.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-devel-2.6.9-78.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.9-78.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-devel-2.6.9-78.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
