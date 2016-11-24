
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(22045);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0577: mutt");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0577");
 script_set_attribute(attribute: "description", value: '
  Updated mutt packages that fix a security issue are now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Mutt is a text-mode mail user agent.

  A buffer overflow flaw was found in the way Mutt processes an overly
  long namespace from a malicious imap server. In order to exploit this
  flaw a user would have to use Mutt to connect to a malicious IMAP server.
  (CVE-2006-3242)

  Users of Mutt are advised to upgrade to these erratum packages, which
  contain a backported patch to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0577.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-3242");
script_summary(english: "Check for the version of the mutt packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"mutt-1.2.5.1-2.rhel21", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mutt-1.4.1-3.5.rhel3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mutt-1.4.1-11.rhel4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
