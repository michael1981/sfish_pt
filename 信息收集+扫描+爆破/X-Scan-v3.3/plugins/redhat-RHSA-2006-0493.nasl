
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(21592);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0493: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0493");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix several security issues in the Red Hat
  Enterprise Linux 4 kernel are now available.

  This security advisory has been rated as having important security impact
  by the Red Hat Security Response Team.

  The Linux kernel handles the basic functions of the operating system.

  These new kernel packages contain fixes for the security issues
  described below:

  * a flaw in the IPv6 implementation that allowed a local user to cause a
  denial of service (infinite loop and crash) (CVE-2005-2973, important)

  * a flaw in the bridge implementation that allowed a remote user to
  cause forwarding of spoofed packets via poisoning of the forwarding
  table with already dropped frames (CVE-2005-3272, moderate)

  * a flaw in the atm module that allowed a local user to cause a denial
  of service (panic) via certain socket calls (CVE-2005-3359, important)

  * a flaw in the NFS client implementation that allowed a local user to
  cause a denial of service (panic) via O_DIRECT writes (CVE-2006-0555,
  important)

  * a difference in "sysretq" operation of EM64T (as opposed to Opteron)
  processors that allowed a local user to cause a denial of service
  (crash) upon return from certain system calls (CVE-2006-0741 and
  CVE-2006-0744, important)

  * a flaw in the keyring implementation that allowed a local user to
  cause a denial of service (OOPS) (CVE-2006-1522, important)

  * a flaw in IP routing implementation that allowed a local user to cause
  a denial of service (panic) via a request for a route for a multicast IP
  (CVE-2006-1525, important)

  * a flaw in the SCTP-netfilter implementation that allowed a remote user
  to cause a denial of service (infinite loop) (CVE-2006-1527, important)

  * a flaw in the sg driver that allowed a local user to cause a denial of
  service (crash) via a dio transfer to memory mapped (mmap) IO space
  (CVE-2006-1528, important)

  * a flaw in the threading implementation that allowed a local user to
  cause a denial of service (panic) (CVE-2006-1855, important)

  * two missing LSM hooks that allowed a local user to bypass the LSM by
  using readv() or writev() (CVE-2006-1856, moderate)

  * a flaw in the virtual memory implementation that allowed local user to
  cause a denial of service (panic) by using the lsof command
  (CVE-2006-1862, important)

  * a directory traversal vulnerability in smbfs that allowed a local user
  to escape chroot restrictions for an SMB-mounted filesystem via "..\\\\"
  sequences (CVE-2006-1864, moderate)

  * a flaw in the ECNE chunk handling of SCTP that allowed a remote user
  to cause a denial of service (panic) (CVE-2006-2271, moderate)

  * a flaw in the handling of COOKIE_ECHO and HEARTBEAT control chunks of
  SCTP that allowed a remote user to cause a denial of service (panic)
  (CVE-2006-2272, moderate)

  * a flaw in the handling of DATA fragments of SCTP that allowed a remote
  user to cause a denial of service (infinite recursion and crash)
  (CVE-2006-2274, moderate)


  All Red Hat Enterprise Linux 4 users are advised to upgrade their kernels
  to the packages associated with their machine architectures and
  configurations as listed in this erratum.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0493.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-2973", "CVE-2005-3272", "CVE-2005-3359", "CVE-2006-0555", "CVE-2006-0741", "CVE-2006-0744", "CVE-2006-1522", "CVE-2006-1525", "CVE-2006-1527", "CVE-2006-1528", "CVE-2006-1855", "CVE-2006-1856", "CVE-2006-1862", "CVE-2006-1864", "CVE-2006-2271", "CVE-2006-2272", "CVE-2006-2274");
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

if ( rpm_check( reference:"kernel-2.6.9-34.0.1.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.9-34.0.1.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.9-34.0.1.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.6.9-34.0.1.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-devel-2.6.9-34.0.1.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.9-34.0.1.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-devel-2.6.9-34.0.1.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
