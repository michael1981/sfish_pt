
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34288);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2008-0885: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0885");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix various security issues and several bugs
  are now available for Red Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  Security fixes:

  * a missing capability check was found in the Linux kernel do_change_type
  routine. This could allow a local unprivileged user to gain privileged
  access or cause a denial of service. (CVE-2008-2931, Important)

  * a flaw was found in the Linux kernel Direct-IO implementation. This could
  allow a local unprivileged user to cause a denial of service.
  (CVE-2007-6716, Important)

  * Tobias Klein reported a missing check in the Linux kernel Open Sound
  System (OSS) implementation. This deficiency could lead to a possible
  information leak. (CVE-2008-3272, Moderate)

  * a deficiency was found in the Linux kernel virtual filesystem (VFS)
  implementation. This could allow a local unprivileged user to attempt file
  creation within deleted directories, possibly causing a denial of service.
  (CVE-2008-3275, Moderate)

  * a flaw was found in the Linux kernel tmpfs implementation. This could
  allow a local unprivileged user to read sensitive information from the
  kernel. (CVE-2007-6417, Moderate)

  Bug fixes:

  * when copying a small IPoIB packet from the original skb it was received
  in to a new, smaller skb, all fields in the new skb were not initialized.
  This may have caused a kernel oops.

  * previously, data may have been written beyond the end of an array,
  causing memory corruption on certain systems, resulting in hypervisor
  crashes during context switching.

  * a kernel crash may have occurred on heavily-used Samba servers after 24
  to 48 hours of use.

  * under heavy memory pressure, pages may have been swapped out from under
  the SGI Altix XPMEM driver, causing silent data corruption in the kernel.

  * the ixgbe driver is untested, but support was advertised for the Intel
  82598 network card. If this card was present when the ixgbe driver was
  loaded, a NULL pointer dereference and a panic occurred.

  * on certain systems, if multiple InfiniBand queue pairs simultaneously
  fell into an error state, an overrun may have occurred, stopping traffic.

  * with bridging, when forward delay was set to zero, setting an interface
  to the forwarding state was delayed by one or possibly two timers,
  depending on whether STP was enabled. This may have caused long delays in
  moving an interface to the forwarding state. This issue caused packet loss
  when migrating virtual machines, preventing them from being migrated
  without interrupting applications.

  * on certain multinode systems, IPMI device nodes were created in reverse
  order of where they physically resided.

  * process hangs may have occurred while accessing application data files
  via asynchronous direct I/O system calls.

  * on systems with heavy lock traffic, a possible deadlock may have caused
  anything requiring locks over NFS to stop, or be very slow. Errors such as
  "lockd: server [IP] not responding, timed out" were logged on client
  systems.

  * unexpected removals of USB devices may have caused a NULL pointer
  dereference in kobject_get_path.

  * on Itanium-based systems, repeatedly creating and destroying Windows
  guests may have caused Dom0 to crash, due to the "XENMEM_add_to_physmap"
  hypercall, used by para-virtualized drivers on HVM, being SMP-unsafe.

  * when using an MD software RAID, crashes may have occurred when devices
  were removed or changed while being iterated through. Correct locking is
  now used.

  * break requests had no effect when using "Serial Over Lan" with the Intel
  82571 network card. This issue may have caused log in problems.

  * on Itanium-based systems, module_free() referred the first parameter
  before checking it was valid. This may have caused a kernel panic when
  exiting SystemTap.

  Red Hat Enterprise Linux 5 users are advised to upgrade to these updated
  packages, which contain backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0885.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-6417", "CVE-2007-6716", "CVE-2008-2931", "CVE-2008-3272", "CVE-2008-3275");
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

if ( rpm_check( reference:"kernel-2.6.18-92.1.13.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-2.6.18-92.1.13.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-devel-2.6.18-92.1.13.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.18-92.1.13.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-devel-2.6.18-92.1.13.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.18-92.1.13.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.18-92.1.13.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.6.18-92.1.13.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.18-92.1.13.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-devel-2.6.18-92.1.13.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
