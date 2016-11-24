
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(16108);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-005: fam");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-005");
 script_set_attribute(attribute: "description", value: '
  Updated fam packages that fix an information disclosure bug are now
  available.

  FAM, the File Alteration Monitor, provides a daemon and an API which
  applications can use for notification of changes in specific files or
  directories.

  A bug has been found in the way FAM handles group permissions. It is
  possible that a local unprivileged user can use a flaw in FAM\'s group
  handling to discover the names of files which are only viewable to users in
  the \'root\' group. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2002-0875 to this issue. This
  issue only affects the version of FAM shipped with Red Hat Enterprise Linux
  2.1.

  Users of FAM should update to these updated packages which contain
  backported patches and are not vulnerable to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-005.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2002-0875");
script_summary(english: "Check for the version of the fam packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"fam-2.6.4-12", release:'RHEL2.1') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fam-devel-2.6.4-12", release:'RHEL2.1') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
