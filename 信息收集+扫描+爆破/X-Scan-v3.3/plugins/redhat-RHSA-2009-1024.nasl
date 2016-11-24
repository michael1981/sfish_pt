
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(38818);
 script_version ("$Revision: 1.3 $");
 script_name(english: "RHSA-2009-1024: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1024");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages are now available as part of the ongoing support
  and maintenance of Red Hat Enterprise Linux version 4. This is the eighth
  regular update.

  These updated packages fix two security issues, hundreds of bugs, and add
  numerous enhancements. Space precludes a detailed description of each of
  these in this advisory. Refer to the Red Hat Enterprise Linux 4.8 Release
  Notes for information on 22 of the most significant of these changes. For
  more detailed information on specific bug fixes or enhancements, refer to
  the Bugzilla numbers associated with this advisory.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  Security Fixes:

  * the exit_notify() function in the Linux kernel did not properly reset the
  exit signal if a process executed a set user ID (setuid) application before
  exiting. This could allow a local, unprivileged user to elevate their
  privileges. (CVE-2009-1337, Important)

  * the Linux kernel implementation of the Network File System (NFS) did not
  properly initialize the file name limit in the nfs_server data structure.
  This flaw could possibly lead to a denial of service on a client mounting
  an NFS share. (CVE-2009-1336, Moderate)

  Bug Fixes and Enhancements:

  Kernel Feature Support:

  * added a new allowable value to "/proc/sys/kernel/wake_balance" to allow
  the scheduler to run the thread on any available CPU rather than scheduling
  it on the optimal CPU.
  * added "max_writeback_pages" tunable parameter to /proc/sys/vm/ to allow
  the maximum number of modified pages kupdate writes to disk, per iteration
  per run.
  * added "swap_token_timeout" tunable parameter to /proc/sys/vm/ to provide
  a valid hold time for the swap out protection token.
  * added diskdump support to sata_svw driver.
  * limited physical memory to 64GB for 32-bit kernels running on systems
  with more than 64GB of physical memory to prevent boot failures.
  * improved reliability of autofs.
  * added support for \'rdattr_error\' in NFSv4 readdir requests.
  * fixed various short packet handling issues for NFSv4 readdir and sunrpc.
  * fixed several CIFS bugs.

  Networking and IPv6 Enablement:

  * added router solicitation support.
  * enforced sg requires tx csum in ethtool.

  Platform Support:

  x86, AMD64, Intel 64, IBM System z

  * added support for a new Intel chipset.
  * added initialization vendor info in boot_cpu_data.
  * added support for N_Port ID Virtualization (NPIV) for IBM System z guests
  using zFCP.
  * added HDMI support for some AMD and ATI chipsets.
  * updated HDA driver in ALSA to latest upstream as of 2008-07-22.
  * added support for affected_cpus for cpufreq.
  * removed polling timer from i8042.
  * fixed PM-Timer when using the ASUS A8V Deluxe motherboard.
  * backported usbfs_mutex in usbfs.

  64-bit PowerPC:

  * updated eHEA driver from version 0078-04 to 0078-08.
  * updated logging of checksum errors in the eHEA driver.

  Network Driver Updates:

  * updated forcedeth driver to latest upstream version 0.61.
  * fixed various e1000 issues when using Intel ESB2 hardware.
  * updated e1000e driver to upstream version 0.3.3.3-k6.
  * updated igb to upstream version 1.2.45-k2.
  * updated tg3 to upstream version 3.96.
  * updated ixgbe to upstream version 1.3.18-k4.
  * updated bnx2 to upstream version 1.7.9.
  * updated bnx2x to upstream version 1.45.23.
  * fixed bugs and added enhancements for the NetXen NX2031 and NX3031
  products.
  * updated Realtek r8169 driver to support newer network chipsets. All
  variants of RTL810x/RTL8168(9) are now supported.

  Storage Driver Updates:

  * fixed various SCSI issues. Also, the SCSI sd driver now calls the
  revalidate_disk wrapper.
  * fixed a dmraid reduced I/O delay bug in certain configurations.
  * removed quirk aac_quirk_scsi_32 for some aacraid controllers.
  * updated FCP driver on IBM System z systems with support for
  point-to-point connections.
  * updated lpfc to version 8.0.16.46.
  * updated megaraid_sas to version 4.01-RH1.
  * updated MPT Fusion driver to version 3.12.29.00rh.
  * updated qla2xxx firmware to 4.06.01 for 4GB/s and 8GB/s adapters.
  * updated qla2xxx driver to version 8.02.09.00.04.08-d.
  * fixed sata_nv in libsata to disable ADMA mode by default.

  Miscellaneous Updates:

  * upgraded OpenFabrics Alliance Enterprise Distribution (OFED) to version
  1.4.
  * added driver support and fixes for various Wacom tablets.

  Users should install this update, which resolves these issues and adds
  these enhancements.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1024.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-1336", "CVE-2009-1337");
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

if ( rpm_check( reference:"kernel-2.6.9-89.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.9-89.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.9-89.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.6.9-89.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-devel-2.6.9-89.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.9-89.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-devel-2.6.9-89.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.9-89.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-devel-2.6.9-89.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
