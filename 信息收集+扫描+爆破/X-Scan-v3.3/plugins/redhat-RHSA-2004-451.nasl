
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(15411);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2004-451: spamassassin");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-451");
 script_set_attribute(attribute: "description", value: '
  An updated spamassassin package that fixes a denial of service bug when
  parsing malformed messages is now available.

  SpamAssassin provides a way to reduce unsolicited commercial email (SPAM)
  from incoming email.

  A denial of service bug has been found in SpamAssassin versions below 2.64.
  A malicious attacker could construct a message in such a way that would
  cause spamassassin to stop responding, potentially preventing the delivery
  or filtering of email. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2004-0796 to this issue.

  Users of SpamAssassin should update to these updated packages which contain
  a backported patch and is not vulnerable to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-451.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0796");
script_summary(english: "Check for the version of the spamassassin packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"spamassassin-2.55-3.2", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
