
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(22219);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0354: elfutils");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0354");
 script_set_attribute(attribute: "description", value: '
  Updated elfutils packages that address a minor security issue and various
  other issues are now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  The elfutils packages contain a number of utility programs and libraries
  related to the creation and maintenance of executable code.

  The elfutils packages that originally shipped with Red Hat Enterprise Linux 4
  were GPL-licensed versions which lacked some functionality. Previous
  updates provided fully functional versions of elfutils only under the OSL
  license. This update provides a fully functional, GPL-licensed version of
  elfutils.

  In the OSL-licensed elfutils versions provided in previous updates, some
  tools could sometimes crash when given corrupted input files. (CVE-2005-1704)

  Also, when the eu-strip tool was used to create separate debuginfo files
  from relocatable objects such as kernel modules (.ko), the resulting
  debuginfo files (.ko.debug) were sometimes corrupted. Both of these
  problems are fixed in the new version.

  Users of elfutils should upgrade to these updated packages, which resolve
  these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0354.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-1704");
script_summary(english: "Check for the version of the elfutils packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"elfutils-0.97.1-3", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"elfutils-devel-0.97.1-3", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"elfutils-libelf-0.97.1-3", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"elfutils-libelf-devel-0.97.1-3", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
