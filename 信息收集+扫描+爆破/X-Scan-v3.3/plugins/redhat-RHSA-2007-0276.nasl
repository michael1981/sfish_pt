
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25144);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0276: shadow");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0276");
 script_set_attribute(attribute: "description", value: '
  Updated shadow-utils packages that fix a security issue and various bugs
  are now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  The shadow-utils package includes the necessary programs for converting
  UNIX password files to the shadow password format, as well as programs for
  managing user and group accounts.

  A flaw was found in the useradd tool in shadow-utils. A new user\'s
  mailbox, when created, could have random permissions for a short period.
  This could allow a local attacker to read or modify the mailbox.
  (CVE-2006-1174)

  This update also fixes the following bugs:

  * shadow-utils debuginfo package was empty.

  * faillog was unusable on 64-bit systems. It checked every UID from 0 to
  the max UID, which was an excessively large number on 64-bit systems.

  * typo bug in login.defs file

  All users of shadow-utils are advised to upgrade to these updated packages,
  which contain backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0276.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-1174");
script_summary(english: "Check for the version of the shadow packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"shadow-utils-4.0.3-61.RHEL4", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
