
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(23798);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0754: gnupg");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0754");
 script_set_attribute(attribute: "description", value: '
  Updated GnuPG packages that fix two security issues are now available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  GnuPG is a utility for encrypting data and creating digital signatures.

  Tavis Ormandy discovered a stack overwrite flaw in the way GnuPG decrypts
  messages. An attacker could create carefully crafted message that could
  cause
  GnuPG to execute arbitrary code if a victim attempts to decrypt the
  message.
  (CVE-2006-6235)

  A heap based buffer overflow flaw was found in the way GnuPG constructs
  messages to be written to the terminal during an interactive session. An
  attacker could create a carefully crafted message which with user
  interaction
  could cause GnuPG to execute arbitrary code with the permissions of the
  user running GnuPG. (CVE-2006-6169)

  All users of GnuPG are advised to upgrade to this updated package, which
  contains a backported patch to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0754.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-6169", "CVE-2006-6235");
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

if ( rpm_check( reference:"gnupg-1.0.7-20", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnupg-1.2.1-19", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnupg-1.2.6-8", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
