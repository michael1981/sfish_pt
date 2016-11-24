
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(22221);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2006-0575: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0575");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages are now available as part of ongoing support
  and maintenance of Red Hat Enterprise Linux version 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The Linux kernel handles the basic functions of the operating system.

  This is the fourth regular update to Red Hat Enterprise Linux 4.

  New features introduced in this update include:

  * Device Mapper mirroring support

  * IDE diskdump support

  * x86, AMD64 and Intel EM64T: Multi-core scheduler support enhancements

  * Itanium: perfmon support for Montecito

  * much improved support for IBM x460

  * AMD PowerNow! patches to support Opteron Rev G

  * Vmalloc support > 64MB

  The following device drivers have been upgraded to new versions:

  ipmi: 33.11 to 33.13
  ib_mthca: 0.06 to 0.08
  bnx2: 1.4.30 to 1.4.38
  bonding: 2.6.1 to 2.6.3
  e100: 3.4.8-k2-NAPI to 3.5.10-k2-NAPI
  e1000: 6.1.16-k3-NAPI to 7.0.33-k2-NAPI
  sky2: 0.13 to 1.1
  tg3: 3.43-rh to 3.52-rh
  ipw2100: 1.1.0 to git-1.1.4
  ipw2200: 1.0.0 to git-1.0.10
  3w-9xxx: 2.26.02.001 to 2.26.04.010
  ips: 7.10.18 to 7.12.02
  iscsi_sfnet: 4:0.1.11-2 to 4:0.1.11-3
  lpfc: 0:8.0.16.18 to 0:8.0.16.27
  megaraid_sas: 00.00.02.00 to 00.00.02.03-RH1
  qla2xxx: 8.01.02-d4 to 8.01.04-d7
  qla6312: 8.01.02-d4 to 8.01.04-d7
  sata_promise: 1.03 to 1.04
  sata_vsc: 1.1 to 1.2
  ibmvscsic: 1.5.5 to 1.5.6
  ipr: 2.0.11.1 to 2.0.11.2

  Added drivers:

  dcdbas: 5.6.0-2
  sata_mv: 0.6
  sata_qstor: 0.05
  sata_uli: 0.5
  skge: 1.1
  stex: 2.9.0.13
  pdc_adma: 0.03

  This update includes fixes for the security issues:

  * a flaw in the USB devio handling of device removal that allowed a
  local user to cause a denial of service (crash) (CVE-2005-3055,
  moderate)

  * a flaw in the ACL handling of nfsd that allowed a remote user to
  bypass ACLs for readonly mounted NFS file systems (CVE-2005-3623,
  moderate)

  * a flaw in the netfilter handling that allowed a local user with
  CAP_NET_ADMIN rights to cause a buffer overflow (CVE-2006-0038, low)

  * a flaw in the IBM S/390 and IBM zSeries strnlen_user() function that
  allowed a local user to cause a denial of service (crash) or to retrieve
  random kernel data (CVE-2006-0456, important)

  * a flaw in the keyctl functions that allowed a local user to cause a
  denial of service (crash) or to read sensitive kernel memory
  (CVE-2006-0457, important)

  * a flaw in unaligned accesses handling on Itanium processors that
  allowed a local user to cause a denial of service (crash)
  (CVE-2006-0742, important)

  * a flaw in SELinux ptrace logic that allowed a local user with ptrace
  permissions to change the tracer SID to a SID of another process
  (CVE-2006-1052, moderate)

  * an info leak on AMD-based x86 and x86_64 systems that allowed a local
  user to retrieve the floating point exception state of a process run by a
  different user (CVE-2006-1056, important)

  * a flaw in IPv4 packet output handling that allowed a remote user to
  bypass the zero IP ID countermeasure on systems with a disabled firewall
  (CVE-2006-1242, low)

  * a minor info leak in socket option handling in the network code
  (CVE-2006-1343, low)

  * a flaw in the HB-ACK chunk handling of SCTP that allowed a remote user to
  cause a denial of service (crash) (CVE-2006-1857, moderate)

  * a flaw in the SCTP implementation that allowed a remote user to cause a
  denial of service (deadlock) (CVE-2006-2275, moderate)

  * a flaw in the socket buffer handling that allowed a remote user to cause
  a denial of service (panic) (CVE-2006-2446, important)

  * a flaw in the signal handling access checking on PowerPC that allowed a
  local user to cause a denial of service (crash) or read arbitrary kernel
  memory on 64-bit systems (CVE-2006-2448, important)

  * a flaw in the netfilter SCTP module when receiving a chunkless packet
  that allowed a remote user to cause a denial of service (crash)
  (CVE-2006-2934, important)

  There were several bug fixes in various parts of the kernel. The ongoing
  effort to resolve these problems has resulted in a marked improvement
  in the reliability and scalability of Red Hat Enterprise Linux 4.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0575.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-3055", "CVE-2005-3623", "CVE-2006-0038", "CVE-2006-0456", "CVE-2006-0457", "CVE-2006-0742", "CVE-2006-1052", "CVE-2006-1056", "CVE-2006-1242", "CVE-2006-1343", "CVE-2006-1857", "CVE-2006-2275", "CVE-2006-2446", "CVE-2006-2448", "CVE-2006-2934");
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

if ( rpm_check( reference:"kernel-2.6.9-42.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.9-42.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.9-42.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.6.9-42.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-devel-2.6.9-42.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.9-42.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-devel-2.6.9-42.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
