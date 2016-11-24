
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(21672);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0543: spamassassin");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0543");
 script_set_attribute(attribute: "description", value: '
  Updated spamassassin packages that fix an arbitrary code execution flaw
  are now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  SpamAssassin provides a way to reduce unsolicited commercial email (SPAM)
  from incoming email.

  A flaw was found with the way the Spamassassin spamd daemon processes the
  virtual pop username passed to it. If a site is running spamd with both the
  --vpopmail and --paranoid flags, it is possible for a remote user with the
  ability to connect to the spamd daemon to execute arbitrary commands as
  the user running the spamd daemon. (CVE-2006-2447)

  Note: None of the IMAP or POP servers shipped with Red Hat Enterprise Linux
  4 support vpopmail delivery. Running spamd with the --vpopmail and
  --paranoid flags is uncommon and not the default startup option as shipped
  with Red Hat Enterprise Linux 4.

  Spamassassin, as shipped in Red Hat Enterprise Linux 4, performs RBL
  lookups against visi.com to help determine if an email is spam. However,
  this DNS RBL has recently disappeared, resulting in mail filtering delays
  and timeouts.

  Users of SpamAssassin should upgrade to these updated packages containing
  version 3.0.6 and backported patches, which are not vulnerable to these
  issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0543.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-2447");
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

if ( rpm_check( reference:"spamassassin-3.0.6-1.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
