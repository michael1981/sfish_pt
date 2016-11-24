
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25686);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0595: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0595");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix a security issue and a bug in the Red Hat
  Enterprise Linux 5 kernel are now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The Linux kernel handles the basic functions of the operating system.

  These new kernel packages contain a fix for the following security issue:

  * a flaw in the signal handling on PowerPC-based systems that allowed a
  local user to cause a denial of service (floating point corruption).
  (CVE-2007-3107, Moderate).

  In addition to the security issue described above, a fix for the following
  have been included:

  * a bug that can lead to data corruption with ServerWorks IDE controllers.

  Red Hat Enterprise Linux 5 users are advised to upgrade to these packages,
  which contain backported patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0595.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-3107");
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

if ( rpm_check( reference:"kernel-2.6.18-8.1.8.el5", release:'RHEL5') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-2.6.18-8.1.8.el5", release:'RHEL5') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-devel-2.6.18-8.1.8.el5", release:'RHEL5') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.18-8.1.8.el5", release:'RHEL5') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.18-8.1.8.el5", release:'RHEL5') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.6.18-8.1.8.el5", release:'RHEL5') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.18-8.1.8.el5", release:'RHEL5') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-devel-2.6.18-8.1.8.el5", release:'RHEL5') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
