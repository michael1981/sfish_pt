
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29203);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2007-1049:   kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-1049");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix several security issues and a bug in the
  Red Hat Enterprise Linux 3 kernel are now available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  A flaw was found in the handling of process death signals. This allowed a
  local user to send arbitrary signals to the suid-process executed by that
  user. A successful exploitation of this flaw depends on the structure of
  the suid-program and its signal handling. (CVE-2007-3848, Important)

  A flaw was found in the IPv4 forwarding base. This allowed a local user to
  cause a denial of service. (CVE-2007-2172, Important)

  A flaw was found where a corrupted executable file could cause cross-region
  memory mappings on Itanium systems. This allowed a local user to cause a
  denial of service. (CVE-2006-4538, Moderate)

  A flaw was found in the stack expansion when using the hugetlb kernel on
  PowerPC systems. This allowed a local user to cause a denial of service.
  (CVE-2007-3739, Moderate)

  A flaw was found in the aacraid SCSI driver. This allowed a local user to
  make ioctl calls to the driver that should be restricted to privileged
  users. (CVE-2007-4308, Moderate)

  As well, these updated packages fix the following bug:

  * a bug in the TCP header prediction code may have caused "TCP: Treason
  uncloaked!" messages to be logged. In certain situations this may have lead
  to TCP connections hanging or aborting.

  Red Hat Enterprise Linux 3 users are advised to upgrade to these updated
  packages, which contain backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-1049.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-4538", "CVE-2007-2172", "CVE-2007-3739", "CVE-2007-3848", "CVE-2007-4308");
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

if ( rpm_check( reference:"  kernel-2.4.21-53.EL.athlon.rpm                        5ed3ebaa27fe3523e6287afe9da778df", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.21-53.EL", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.21-53.EL", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.21-53.EL", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.4.21-53.EL", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-unsupported-2.4.21-53.EL", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-2.4.21-53.EL.athlon.rpm                    b6966cff1cca0a9b4c53f7ac8bc7c8ec", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.21-53.EL", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-unsupported-2.4.21-53.EL.athlon.rpm        e1f6b9b5f82534206d68de57173cebc7", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-unsupported-2.4.21-53.EL", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-53.EL", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-unsupported-2.4.21-53.EL.athlon.rpm            38292e5677afeca19eff46011643b687", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-unsupported-2.4.21-53.EL", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
