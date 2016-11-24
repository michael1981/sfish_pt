
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12410);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2003-239:   kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-239");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that address various security vulnerabilities are
  now available for Red Hat Enterprise Linux.

  The Linux kernel handles the basic functions of the operating system.

  Security issues have been found that affect the versions of the Linux
  kernel shipped with Red Hat Enterprise Linux:

  CAN-2003-0462: Paul Starzetz discovered a file read race condition existing
  in the execve() system call, which could cause a local crash.

  CAN-2003-0501: The /proc filesystem in Linux allows local users to obtain
  sensitive information by opening various entries in /proc/self before
  executing a setuid program. This causes the program to fail to change the
  ownership and permissions of already opened entries.

  CAN-2003-0550: The STP protocol is known to have no security, which could
  allow attackers to alter the bridge topology. STP is now turned off by
  default.

  CAN-2003-0551: STP input processing was lax in its length checking, which
  could lead to a denial of service (DoS).

  CAN-2003-0552: Jerry Kreuscher discovered that the Forwarding table could
  be spoofed by sending forged packets with bogus source addresses the same
  as the local host.

  CAN-2003-0619: An integer signedness error in the decode_fh function of
  nfs3xdr.c allows remote attackers to cause a denial of service (kernel
  panic) via a negative size value within XDR data of an NFSv3 procedure
  call.

  CAN-2003-0699: The C-Media PCI sound driver in Linux kernel versions prior
  to 2.4.21 accesses userspace without using the get_user function, which is
  a potential security hole.

  All users are advised to upgrade to these erratum packages, which contain
  backported security patches correcting these vulnerabilities.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-239.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0462", "CVE-2003-0501", "CVE-2003-0550", "CVE-2003-0551", "CVE-2003-0552", "CVE-2003-0619", "CVE-2003-0699");
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

if ( rpm_check( reference:"  kernel-2.4.9-e.27.athlon.rpm               973c3e760fed61273c7bef02631a2418", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.9-e.27", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.9-e.27", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.4.9-e.27", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.9-e.27", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.4.9-e.27", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.4.9-e.27", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-2.4.9-e.27.athlon.rpm           3e269b2912a3b1441cfceea1d8af7924", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.9-e.27", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.9-e.27", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-summit-2.4.9-e.27", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
