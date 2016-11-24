
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42360);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2009-1550:   kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1550");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix several security issues and multiple bugs
  are now available for Red Hat Enterprise Linux 3.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  Security fixes:

  * when fput() was called to close a socket, the __scm_destroy() function in
  the Linux kernel could make indirect recursive calls to itself. This could,
  potentially, lead to a denial of service issue. (CVE-2008-5029, Important)

  * the sendmsg() function in the Linux kernel did not block during UNIX
  socket garbage collection. This could, potentially, lead to a local denial
  of service. (CVE-2008-5300, Important)

  * the exit_notify() function in the Linux kernel did not properly reset the
  exit signal if a process executed a set user ID (setuid) application before
  exiting. This could allow a local, unprivileged user to elevate their
  privileges. (CVE-2009-1337, Important)

  * a flaw was found in the Intel PRO/1000 network driver in the Linux
  kernel. Frames with sizes near the MTU of an interface may be split across
  multiple hardware receive descriptors. Receipt of such a frame could leak
  through a validation check, leading to a corruption of the length check. A
  remote attacker could use this flaw to send a specially-crafted packet that
  would cause a denial of service or code execution. (CVE-2009-1385,
  Important)

  * the ADDR_COMPAT_LAYOUT and MMAP_PAGE_ZERO flags were not cleared when a
  setuid or setgid program was executed. A local, unprivileged user could use
  this flaw to bypass the mmap_min_addr protection mechanism and perform a
  NULL pointer dereference attack, or bypass the Address Space Layout
  Randomization (ASLR) security feature. (CVE-2009-1895, Important)

  * it was discovered that, when executing a new process, the clear_child_tid
  pointer in the Linux kernel is not cleared. If this pointer points to a
  writable portion of the memory of the new program, the kernel could corrupt
  four bytes of memory, possibly leading to a local denial of service or
  privilege escalation. (CVE-2009-2848, Important)

  * missing initialization flaws were found in getname() implementations in
  the IrDA sockets, AppleTalk DDP protocol, NET/ROM protocol, and ROSE
  protocol implementations in the Linux kernel. Certain data structures in
  these getname() implementations were not initialized properly before being
  copied to user-space. These flaws could lead to an information leak.
  (CVE-2009-3002, Important)

  * a NULL pointer dereference flaw was found in each of the following
  functions in the Linux kernel: pipe_read_open(), pipe_write_open(), and
  pipe_rdwr_open(). When the mutex lock is not held, the i_pipe pointer could
  be released by other processes before it is used to update the pipe\'s
  reader and writer counters. This could lead to a local denial of service or
  privilege escalation. (CVE-2009-3547, Important)

  Bug fixes:

  * this update adds the mmap_min_addr tunable and restriction checks to help
  prevent unprivileged users from creating new memory mappings below the
  minimum address. This can help prevent the exploitation of NULL pointer
  dereference bugs. Note that mmap_min_addr is set to zero (disabled) by
  default for backwards compatibility. (BZ#512642)

  * a bridge reference count problem in IPv6 has been fixed. (BZ#457010)

  * enforce null-termination of user-supplied arguments to setsockopt().
  (BZ#505514)

  * the gcc flag "-fno-delete-null-pointer-checks" was added to the kernel
  build options. This prevents gcc from optimizing out NULL pointer checks
  after the first use of a pointer. NULL pointer bugs are often exploited by
  attackers. Keeping these checks is a safety measure. (BZ#511185)

  * a check has been added to the IPv4 code to make sure that rt is not NULL,
  to help prevent future bugs in functions that call ip_append_data() from
  being exploitable. (BZ#520300)

  Users should upgrade to these updated packages, which contain backported
  patches to correct these issues. The system must be rebooted for this
  update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1550.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-5029", "CVE-2008-5300", "CVE-2009-1337", "CVE-2009-1385", "CVE-2009-1895", "CVE-2009-2848", "CVE-2009-3002", "CVE-2009-3547");
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

if ( rpm_check( reference:"  kernel-2.4.21-63.EL.athlon.rpm                        32b4de48919cc75bdb7f58dac9a2ec14", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.21-63.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.21-63.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.21-63.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.4.21-63.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-unsupported-2.4.21-63.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-2.4.21-63.EL.athlon.rpm                    12ed25c2770bd1d14b4801dac446dd00", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.21-63.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-unsupported-2.4.21-63.EL.athlon.rpm        835b2dd3cfa6c54dfc05365236b97d99", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-unsupported-2.4.21-63.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-63.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-unsupported-2.4.21-63.EL.athlon.rpm            ff1ba82929fd18c11fe7c42b025b1e87", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-unsupported-2.4.21-63.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
