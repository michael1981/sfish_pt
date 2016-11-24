
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(30090);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0089: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0089");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix several security issues and several bugs
  in the Red Hat Enterprise Linux 5 kernel are now available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  These new kernel packages fix the following security issues:

  A flaw was found in the virtual filesystem (VFS). An unprivileged local
  user could truncate directories to which they had write permission; this
  could render the contents of the directory inaccessible. (CVE-2008-0001,
  Important)

  A flaw was found in the Xen PAL emulation on Intel 64 platforms. A guest
  Hardware-assisted virtual machine (HVM) could read the arbitrary physical
  memory of the host system, which could make information available to
  unauthorized users. (CVE-2007-6416, Important)

  A flaw was found in the way core dump files were created. If a local user
  can get a root-owned process to dump a core file into a directory, which
  the user has write access to, they could gain read access to that core
  file, potentially containing sensitive information. (CVE-2007-6206, Moderate)

  A buffer overflow flaw was found in the CIFS virtual file system. A
  remote,authenticated user could issue a request that could lead to a denial
  of service. (CVE-2007-5904, Moderate)

  A flaw was found in the "sysfs_readdir" function. A local user could create
  a race condition which would cause a denial of service (kernel oops).
  (CVE-2007-3104, Moderate)

  As well, these updated packages fix the following bugs:

  * running the "strace -f" command caused strace to hang, without displaying
  information about child processes.

  * unmounting an unresponsive, interruptable NFS mount, for example, one
  mounted with the "intr" option, may have caused a system crash.

  * a bug in the s2io.ko driver prevented VLAN devices from being added.
  Attempting to add a device to a VLAN, for example, running the "vconfig
  add [device-name] [vlan-id]" command caused vconfig to fail.

  * tux used an incorrect open flag bit. This caused problems when building
  packages in a chroot environment, such as mock, which is used by the koji
  build system.

  Red Hat Enterprise Linux 5 users are advised to upgrade to these updated
  packages, which contain backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:A/AC:H/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0089.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-3104", "CVE-2007-5904", "CVE-2007-6206", "CVE-2007-6416", "CVE-2008-0001");
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

if ( rpm_check( reference:"kernel-2.6.18-53.1.6.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-2.6.18-53.1.6.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-devel-2.6.18-53.1.6.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.18-53.1.6.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-devel-2.6.18-53.1.6.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.18-53.1.6.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.18-53.1.6.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.6.18-53.1.6.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.18-53.1.6.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-devel-2.6.18-53.1.6.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
