
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(31619);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0196: unzip");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0196");
 script_set_attribute(attribute: "description", value: '
  Updated unzip packages that fix a security issue are now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The unzip utility is used to list, test, or extract files from a zip
  archive.

  An invalid pointer flaw was found in unzip. If a user ran unzip on a
  specially crafted file, an attacker could execute arbitrary code with that
  user\'s privileges. (CVE-2008-0888)

  Red Hat would like to thank Tavis Ormandy of the Google Security Team for
  reporting this issue.

  All unzip users are advised to upgrade to these updated packages, which
  contain a backported patch to resolve this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0196.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-0888");
script_summary(english: "Check for the version of the unzip packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"unzip-5.50-31.EL2.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"unzip-5.50-36.EL3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
