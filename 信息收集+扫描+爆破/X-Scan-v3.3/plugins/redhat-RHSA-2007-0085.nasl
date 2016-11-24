
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(24724);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0085: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0085");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix two security issues and a bug in the Red Hat
  Enterprise Linux 4 kernel are now available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The Linux kernel handles the basic functions of the operating system.

  These new kernel packages contain fixes for two security issues:

  * a flaw in the key serial number collision avoidance algorithm of the
  keyctl subsystem that allowed a local user to cause a denial of service
  (CVE-2007-0006, Important)

  * a flaw in the file watch implementation of the audit subsystems that
  allowed a local user to cause a denial of service (panic). To exploit this
  flaw a privileged user must have previously created a watch for a file
  (CVE-2007-0001, Moderate)

  In addition to the security issues described above, a fix for the SCTP
  subsystem to address a system crash which may be experienced in Telco
  environments has been included.

  Red Hat Enterprise Linux 4 users are advised to upgrade their kernels to
  the packages associated with their machine architecture and configurations
  as listed in this erratum.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0085.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-0001", "CVE-2007-0006");
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

if ( rpm_check( reference:"kernel-2.6.9-42.0.10.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.9-42.0.10.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.9-42.0.10.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.6.9-42.0.10.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-devel-2.6.9-42.0.10.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.9-42.0.10.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-devel-2.6.9-42.0.10.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
