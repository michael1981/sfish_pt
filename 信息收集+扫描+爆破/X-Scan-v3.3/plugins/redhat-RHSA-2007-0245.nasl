
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25141);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0245: cpio");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0245");
 script_set_attribute(attribute: "description", value: '
  An updated cpio package that fixes a security issue and various bugs is now
  available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  GNU cpio copies files into or out of a cpio or tar archive.

  A buffer overflow was found in cpio on 64-bit platforms. By tricking a
  user into adding a specially crafted large file to a cpio archive, a local
  attacker may be able to exploit this flaw to execute arbitrary code with
  the target user\'s privileges. (CVE-2005-4268)

  This erratum also addresses the following bugs:

  * cpio did not set exit codes appropriately.

  * cpio did not create a ram disk properly.

  All users of cpio are advised to upgrade to this updated package, which
  contains backported fixes to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0245.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-4268");
script_summary(english: "Check for the version of the cpio packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"cpio-2.5-13.RHEL4", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
