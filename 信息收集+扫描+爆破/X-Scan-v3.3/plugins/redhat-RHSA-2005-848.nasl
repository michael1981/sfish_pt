
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(20269);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2005-848: libc");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-848");
 script_set_attribute(attribute: "description", value: '
  Updated libc-client packages that fix a buffer overflow issue are now
  available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  C-client is a common API for accessing mailboxes.

  A buffer overflow flaw was discovered in the way C-client parses user
  supplied mailboxes. If an authenticated user requests a specially crafted
  mailbox name, it may be possible to execute arbitrary code on a server that
  uses C-client to access mailboxes. The Common Vulnerabilities and Exposures
  project has assigned the name CVE-2005-2933 to this issue.

  All users of libc-client should upgrade to these updated packages, which
  contain a backported patch that resolves this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-848.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-2933");
script_summary(english: "Check for the version of the libc packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libc-client-2002e-14", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libc-client-devel-2002e-14", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
