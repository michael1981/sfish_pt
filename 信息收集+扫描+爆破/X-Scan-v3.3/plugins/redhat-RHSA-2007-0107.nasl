
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25320);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0107: gnupg");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0107");
 script_set_attribute(attribute: "description", value: '
  Updated GnuPG packages that fix a security issue are now available for Red
  Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  GnuPG is a utility for encrypting data and creating digital signatures.

  Gerardo Richarte discovered that a number of applications that make use of
  GnuPG are prone to a vulnerability involving incorrect verification of
  signatures and encryption. An attacker could add arbitrary content to a
  signed message in such a way that a receiver of the message would not be
  able to distinguish between the properly signed parts of a message and the
  forged, unsigned, parts. (CVE-2007-1263)

  Whilst this is not a vulnerability in GnuPG itself, the GnuPG team have
  produced a patch to protect against messages with multiple plaintext
  packets. Users should update to these erratum packages which contain the
  backported patch for this issue.

  Red Hat would like to thank Core Security Technologies for reporting this
  issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0107.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-1263");
script_summary(english: "Check for the version of the gnupg packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gnupg-1.4.5-13", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
