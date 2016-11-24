
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(18128);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-293:   kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-293");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix several security issues in the Red Hat
  Enterprise Linux 3 kernel are now available.

  This security advisory has been rated as having important security impact
  by the Red Hat Security Response Team.

  The Linux kernel handles the basic functions of the operating system.

  The following security issues were fixed:

  The Vicam USB driver did not use the copy_from_user function to access
  userspace, crossing security boundaries. (CAN-2004-0075)

  The ext3 and jfs code did not properly initialize journal descriptor
  blocks. A privileged local user could read portions of kernel memory.
  (CAN-2004-0177)

  The terminal layer did not properly lock line discipline changes or pending
  IO. An unprivileged local user could read portions of kernel memory, or
  cause a denial of service (system crash). (CAN-2004-0814)

  A race condition was discovered. Local users could use this flaw to read
  the environment variables of another process that is still spawning via
  /proc/.../cmdline. (CAN-2004-1058)

  A flaw in the execve() syscall handling was discovered, allowing a local
  user to read setuid ELF binaries that should otherwise be protected by
  standard permissions. (CAN-2004-1073). Red Hat originally reported this
  as being fixed by RHSA-2004:549, but the associated fix was missing from
  that update.

  Keith Owens reported a flaw in the Itanium unw_unwind_to_user() function.
  A local user could use this flaw to cause a denial of service (system
  crash) on the Itanium architecture. (CAN-2005-0135)

  A missing Itanium syscall table entry could allow an unprivileged
  local user to cause a denial of service (system crash) on the Itanium
  architecture. (CAN-2005-0137)

  A flaw affecting the OUTS instruction on the AMD64 and Intel EM64T
  architectures was discovered. A local user could use this flaw to
  access privileged IO ports. (CAN-2005-0204)

  A flaw was discovered in the Linux PPP driver. On systems allowing remote
  users to connect to a server using ppp, a remote client could cause a
  denial of service (system crash). (CAN-2005-0384)

  A flaw in the Red Hat backport of NPTL to Red Hat Enterprise Linux 3 was
  discovered that left a pointer to a freed tty structure. A local user
  could potentially use this flaw to cause a denial of service (system crash)
  or possibly gain read or write access to ttys that should normally be
  prevented. (CAN-2005-0403)

  A flaw in fragment queuing was discovered affecting the netfilter
  subsystem. On systems configured to filter or process network packets (for
  example those configured to do firewalling), a remote attacker could send a
  carefully crafted set of fragmented packets to a machine and cause a denial
  of service (system crash). In order to sucessfully exploit this flaw, the
  attacker would need to know (or guess) some aspects of the firewall ruleset
  in place on the target system to be able to craft the right fragmented
  packets. (CAN-2005-0449)

  Missing validation of an epoll_wait() system call parameter could allow
  a local user to cause a denial of service (system crash) on the IBM S/390
  and zSeries architectures. (CAN-2005-0736)

  A flaw when freeing a pointer in load_elf_library was discovered. A local
  user could potentially use this flaw to cause a denial of service (system
  crash). (CAN-2005-0749)

  A flaw was discovered in the bluetooth driver system. On system where the
  bluetooth modules are loaded, a local user could use this flaw to gain
  elevated (root) privileges. (CAN-2005-0750)

  In addition to the security issues listed above, there was an important
  fix made to the handling of the msync() system call for a particular case
  in which the call could return without queuing modified mmap()\'ed data for
  file system update. (BZ 147969)

  Note: The kernel-unsupported package contains various drivers and modules
  that are unsupported and therefore might contain security problems that
  have not been addressed.

  Red Hat Enterprise Linux 3 users are advised to upgrade their kernels to
  the packages associated with their machine architectures/configurations

  Please note that the fix for CAN-2005-0449 required changing the
  external symbol linkages (kernel module ABI) for the ip_defrag()
  and ip_ct_gather_frags() functions. Any third-party module using either
  of these would also need to be fixed.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-293.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0075", "CVE-2004-0177", "CVE-2004-0814", "CVE-2004-1058", "CVE-2004-1073", "CVE-2005-0135", "CVE-2005-0137", "CVE-2005-0204", "CVE-2005-0384", "CVE-2005-0403", "CVE-2005-0449", "CVE-2005-0736", "CVE-2005-0749", "CVE-2005-0750");
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

if ( rpm_check( reference:"  kernel-2.4.21-27.0.4.EL.athlon.rpm                        9fbfd848c45689aedc8a8ca6bc695be5", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.21-27.0.4.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.21-27.0.4.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.21-27.0.4.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.4.21-27.0.4.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-unsupported-2.4.21-27.0.4.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-2.4.21-27.0.4.EL.athlon.rpm                    752dcfb04c02b16b28610f62078d7b96", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.21-27.0.4.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-unsupported-2.4.21-27.0.4.EL.athlon.rpm        a6d5f950e96c3ac929cc906a2eee1413", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-unsupported-2.4.21-27.0.4.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-27.0.4.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-unsupported-2.4.21-27.0.4.EL.athlon.rpm            736f0feedd86a8b226016358fab7adb9", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-unsupported-2.4.21-27.0.4.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
