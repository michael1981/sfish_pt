
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35645);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2009-0264: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0264");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that resolve several security issues are now
  available for Red Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  This update addresses the following security issues:

  * a memory leak in keyctl handling. A local user could use this flaw to
  deplete kernel memory, eventually leading to a denial of service.
  (CVE-2009-0031, Important)

  * a buffer overflow in the Linux kernel Partial Reliable Stream Control
  Transmission Protocol (PR-SCTP) implementation. This could, potentially,
  lead to a denial of service if a Forward-TSN chunk is received with a large
  stream ID. (CVE-2009-0065, Important)

  * a flaw when handling heavy network traffic on an SMP system with many
  cores. An attacker who could send a large amount of network traffic could
  create a denial of service. (CVE-2008-5713, Important)

  * the code for the HFS and HFS Plus (HFS+) file systems failed to properly
  handle corrupted data structures. This could, potentially, lead to a local
  denial of service. (CVE-2008-4933, CVE-2008-5025, Low)

  * a flaw was found in the HFS Plus (HFS+) file system implementation. This
  could, potentially, lead to a local denial of service when write operations
  are performed. (CVE-2008-4934, Low)

  In addition, these updated packages fix the following bugs:

  * when using the nfsd daemon in a clustered setup, kernel panics appeared
  seemingly at random. These panics were caused by a race condition in
  the device-mapper mirror target.

  * the clock_gettime(CLOCK_THREAD_CPUTIME_ID, ) syscall returned a smaller
  timespec value than the result of previous clock_gettime() function
  execution, which resulted in a negative, and nonsensical, elapsed time value.

  * nfs_create_rpc_client was called with a "flavor" parameter which was
  usually ignored and ended up unconditionally creating the RPC client with
  an AUTH_UNIX flavor. This caused problems on AUTH_GSS mounts when the
  credentials needed to be refreshed. The credops did not match the
  authorization type, which resulted in the credops dereferencing an
  incorrect part of the AUTH_UNIX rpc_auth struct.

  * when copy_user_c terminated prematurely due to reading beyond the end of
  the user buffer and the kernel jumped to the exception table entry, the rsi
  register was not cleared. This resulted in exiting back to user code with
  garbage in the rsi register.

  * the hexdump data in s390dbf traces was incomplete. The length of the data
  traced was incorrect and the SAN payload was read from a different place
  then it was written to.

  * when using connected mode (CM) in IPoIB on ehca2 hardware, it was not
  possible to transmit any data.

  * when an application called fork() and pthread_create() many times and, at
  some point, a thread forked a child and then attempted to call the
  setpgid() function, then this function failed and returned and ESRCH error
  value.

  Users should upgrade to these updated packages, which contain backported
  patches to correct these issues. Note: for this update to take effect, the
  system must be rebooted.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0264.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-4933", "CVE-2008-4934", "CVE-2008-5025", "CVE-2008-5713", "CVE-2009-0031", "CVE-2009-0065");
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

if ( rpm_check( reference:"kernel-2.6.18-128.1.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-2.6.18-128.1.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-devel-2.6.18-128.1.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.18-128.1.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-devel-2.6.18-128.1.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.18-128.1.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.18-128.1.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.6.18-128.1.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.18-128.1.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-devel-2.6.18-128.1.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
