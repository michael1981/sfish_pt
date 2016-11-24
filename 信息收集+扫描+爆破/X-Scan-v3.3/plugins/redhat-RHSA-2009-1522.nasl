
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42216);
 script_version ("$Revision: 1.1 $");
 script_name(english: "RHSA-2009-1522: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1522");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix multiple security issues and several bugs
  are now available for Red Hat Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  This update fixes the following security issues:

  * multiple, missing initialization flaws were found in the Linux kernel.
  Padding data in several core network structures was not initialized
  properly before being sent to user-space. These flaws could lead to
  information leaks. (CVE-2005-4881, CVE-2009-3228, Moderate)

  This update also fixes the following bugs:

  * a packet duplication issue was fixed via the RHSA-2008:0665 update;
  however, the fix introduced a problem for systems using network bonding:
  Backup slaves were unable to receive ARP packets. When using network
  bonding in the "active-backup" mode and with the "arp_validate=3" option,
  the bonding driver considered such backup slaves as being down (since they
  were not receiving ARP packets), preventing successful failover to these
  devices. (BZ#519384)

  * due to insufficient memory barriers in the network code, a process
  sleeping in select() may have missed notifications about new data. In rare
  cases, this bug may have caused a process to sleep forever. (BZ#519386)

  * the driver version number in the ata_piix driver was not changed between
  Red Hat Enterprise Linux 4.7 and Red Hat Enterprise Linux 4.8, even though
  changes had been made between these releases. This could have prevented the
  driver from loading on systems that check driver versions, as this driver
  appeared older than it was. (BZ#519389)

  * a bug in nlm_lookup_host() could have led to un-reclaimed locks on file
  systems, resulting in the umount command failing. This bug could have also
  prevented NFS services from being relocated correctly in clustered
  environments. (BZ#519656)

  * the data buffer ethtool_get_strings() allocated, for the igb driver, was
  smaller than the amount of data that was copied in igb_get_strings(),
  because of a miscalculation in IGB_QUEUE_STATS_LEN, resulting in memory
  corruption. This bug could have led to a kernel panic. (BZ#522738)

  * in some situations, write operations to a TTY device were blocked even
  when the O_NONBLOCK flag was used. A reported case of this issue occurred
  when a single TTY device was opened by two users (one using blocking mode,
  and the other using non-blocking mode). (BZ#523930)

  * a deadlock was found in the cciss driver. In rare cases, this caused an
  NMI lockup during boot. Messages such as "cciss: controller cciss[x]
  failed, stopping." and "cciss[x]: controller not responding." may have
  been displayed on the console. (BZ#525725)

  * on 64-bit PowerPC systems, a rollover bug in the ibmveth driver could
  have caused a kernel panic. In a reported case, this panic occurred on a
  system with a large uptime and under heavy network load. (BZ#527225)

  Users should upgrade to these updated packages, which contain backported
  patches to correct these issues. The system must be rebooted for this
  update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1522.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-4881", "CVE-2009-3228");
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

if ( rpm_check( reference:"kernel-2.6.9-89.0.15.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.9-89.0.15.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.9-89.0.15.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.6.9-89.0.15.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-devel-2.6.9-89.0.15.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.9-89.0.15.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-devel-2.6.9-89.0.15.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.9-89.0.15.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-devel-2.6.9-89.0.15.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.6.9-89.0.15.EL", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.9-89.0.15.EL", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.9-89.0.15.EL", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.6.9-89.0.15.EL", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-devel-2.6.9-89.0.15.EL", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.9-89.0.15.EL", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-devel-2.6.9-89.0.15.EL", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.9-89.0.15.EL", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-devel-2.6.9-89.0.15.EL", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
