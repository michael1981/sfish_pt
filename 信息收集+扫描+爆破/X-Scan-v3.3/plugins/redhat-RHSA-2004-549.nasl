
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(15944);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2004-549:   kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-549");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix several security issues in Red Hat
  Enterprise Linux 3 are now available.

  The Linux kernel handles the basic functions of the operating system.

  This update includes fixes for several security issues:

  A missing serialization flaw in unix_dgram_recvmsg was discovered that
  affects kernels prior to 2.4.28. A local user could potentially make
  use of a race condition in order to gain privileges. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2004-1068 to this issue.

  Paul Starzetz of iSEC discovered various flaws in the ELF binary
  loader affecting kernels prior to 2.4.28. A local user could use thse
  flaws to gain read access to executable-only binaries or possibly gain
  privileges. (CAN-2004-1070, CAN-2004-1071, CAN-2004-1072, CAN-2004-1073)

  A flaw when setting up TSS limits was discovered that affects AMD AMD64
  and Intel EM64T architecture kernels prior to 2.4.23. A local user could
  use this flaw to cause a denial of service (crash) or possibly gain
  privileges. (CAN-2004-0812)

  An integer overflow flaw was discovered in the ubsec_keysetup function
  in the Broadcom 5820 cryptonet driver. On systems using this driver,
  a local user could cause a denial of service (crash) or possibly gain
  elevated privileges. (CAN-2004-0619)

  Stefan Esser discovered various flaws including buffer overflows in
  the smbfs driver affecting kernels prior to 2.4.28. A local user may be
  able to cause a denial of service (crash) or possibly gain privileges.
  In order to exploit these flaws the user would require control of
  a connected Samba server. (CAN-2004-0883, CAN-2004-0949)

  SGI discovered a bug in the elf loader that affects kernels prior to
  2.4.25 which could be triggered by a malformed binary. On
  architectures other than x86, a local user could create a malicious
  binary which could cause a denial of service (crash). (CAN-2004-0136)

  Conectiva discovered flaws in certain USB drivers affecting kernels
  prior to 2.4.27 which used the copy_to_user function on uninitialized
  structures. These flaws could allow local users to read small amounts
  of kernel memory. (CAN-2004-0685)

  All Red Hat Enterprise Linux 3 users are advised to upgrade their
  kernels to the packages associated with their machine architectures
  and configurations as listed in this erratum.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-549.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0138", "CVE-2004-0619", "CVE-2004-0685", "CVE-2004-0812", "CVE-2004-0883", "CVE-2004-0949", "CVE-2004-1068", "CVE-2004-1070", "CVE-2004-1071", "CVE-2004-1072", "CVE-2004-1073");
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

if ( rpm_check( reference:"  kernel-2.4.21-20.0.1.EL.athlon.rpm                        f8c081ece832012d2336fdd79e4deb60", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.21-20.0.1.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.21-20.0.1.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.21-20.0.1.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.4.21-20.0.1.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-unsupported-2.4.21-20.0.1.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-2.4.21-20.0.1.EL.athlon.rpm                    fdb4239f2bb030111db06b4d97db5caf", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.21-20.0.1.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-unsupported-2.4.21-20.0.1.EL.athlon.rpm        da055118ecfa029bdb09fdb8ebb1d955", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-unsupported-2.4.21-20.0.1.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-20.0.1.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-unsupported-2.4.21-20.0.1.EL.athlon.rpm            fa9407f23524f3ed308564adfcfeb175", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-unsupported-2.4.21-20.0.1.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
