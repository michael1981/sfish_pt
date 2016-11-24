
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(20751);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0140:   kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0140");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix several security issues in the Red Hat
  Enterprise Linux 3 kernel are now available.

  This security advisory has been rated as having important security impact
  by the Red Hat Security Response Team.

  The Linux kernel handles the basic functions of the operating system.

  These new kernel packages contain fixes for the security issues
  described below:

  - a flaw in network IGMP processing that a allowed a remote user on the
  local network to cause a denial of service (disabling of multicast reports)
  if the system is running multicast applications (CVE-2002-2185, moderate)

  - a flaw in remap_page_range() with O_DIRECT writes that allowed a local
  user to cause a denial of service (crash) (CVE-2004-1057, important)

  - a flaw in exec() handling on some 64-bit architectures that allowed
  a local user to cause a denial of service (crash) (CVE-2005-2708, important)

  - a flaw in procfs handling during unloading of modules that allowed a
  local user to cause a denial of service or potentially gain privileges
  (CVE-2005-2709, moderate)

  - a flaw in IPv6 network UDP port hash table lookups that allowed a local
  user to cause a denial of service (hang) (CVE-2005-2973, important)

  - a flaw in 32-bit-compat handling of the TIOCGDEV ioctl that allowed
  a local user to cause a denial of service (crash) (CVE-2005-3044, important)

  - a network buffer info leak using the orinoco driver that allowed
  a remote user to possibly view uninitialized data (CVE-2005-3180, important)

  - a flaw in IPv4 network TCP and UDP netfilter handling that allowed
  a local user to cause a denial of service (crash) (CVE-2005-3275, important)

  - a flaw in the IPv6 flowlabel code that allowed a local user to cause a
  denial of service (crash) (CVE-2005-3806, important)

  - a flaw in network ICMP processing that allowed a local user to cause
  a denial of service (memory exhaustion) (CVE-2005-3848, important)

  - a flaw in file lease time-out handling that allowed a local user to cause
  a denial of service (log file overflow) (CVE-2005-3857, moderate)

  - a flaw in network IPv6 xfrm handling that allowed a local user to
  cause a denial of service (memory exhaustion) (CVE-2005-3858, important)

  All Red Hat Enterprise Linux 3 users are advised to upgrade their kernels
  to the packages associated with their machine architecture and
  configurations as listed in this erratum.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0140.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2002-2185", "CVE-2004-1057", "CVE-2005-2708", "CVE-2005-2709", "CVE-2005-2973", "CVE-2005-3044", "CVE-2005-3180", "CVE-2005-3275", "CVE-2005-3806", "CVE-2005-3848", "CVE-2005-3857", "CVE-2005-3858");
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

if ( rpm_check( reference:"  kernel-2.4.21-37.0.1.EL.athlon.rpm                        c132a984fc36125635ed8c9dfea0aafe", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.21-37.0.1.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.21-37.0.1.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.21-37.0.1.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.4.21-37.0.1.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-unsupported-2.4.21-37.0.1.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-2.4.21-37.0.1.EL.athlon.rpm                    29c4165c6982cbe8cdcca4e544898fd3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.21-37.0.1.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-unsupported-2.4.21-37.0.1.EL.athlon.rpm        c51f8fa5df41bb2d894d1d93c1ea16fd", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-unsupported-2.4.21-37.0.1.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-37.0.1.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-unsupported-2.4.21-37.0.1.EL.athlon.rpm            1dfc561d293146a44a9b96e58a283260", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-unsupported-2.4.21-37.0.1.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
