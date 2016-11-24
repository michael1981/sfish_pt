
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33586);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0780: coreutils");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0780");
 script_set_attribute(attribute: "description", value: '
  Updated coreutils packages that fix a security issue are now available for
  Red Hat Enterprise Linux 4.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  The coreutils package contains the core GNU utilities. It is the
  combination of the old GNU fileutils, sh-utils, and textutils packages.

  The coreutils packages were found to not use the pam_succeed_if Pluggable
  Authentication Module (PAM) correctly in the configuration file for the
  "su" command. Any local user could use this command to change to a locked
  or expired user account if the target account\'s password was known to the
  user running "su". These updated packages, correctly, only allow the root
  user to switch to locked or expired accounts using "su". (CVE-2008-1946)

  All users of coreutils are advised to upgrade to this updated package,
  which resolve this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0780.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-1946");
script_summary(english: "Check for the version of the coreutils packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"coreutils-5.2.1-31.8.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
