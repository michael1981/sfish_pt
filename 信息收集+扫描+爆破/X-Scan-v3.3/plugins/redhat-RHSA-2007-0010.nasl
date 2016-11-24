
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(24676);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0010: koffice");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0010");
 script_set_attribute(attribute: "description", value: '
  Updated KOffice packages that fix a security issue are now available for
  Red Hat Enterprise Linux 2.1.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  KOffice is a collection of productivity applications for the K Desktop
  Environment (KDE) GUI desktop.

  An integer overflow bug was found in KOffice\'s PPT file processor. An
  attacker could create a malicious PPT file that could cause KOffice to
  execute arbitrary code if the file was opened by a victim. (CVE-2006-6120)

  All users of KOffice are advised to upgrade to these updated packages,
  which
  contains a backported patch to correct this issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0010.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-6120");
script_summary(english: "Check for the version of the koffice packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"koffice-1.1.1-2.3", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"koffice-devel-1.1.1-2.3", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
