
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12335);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2002-259: sendmail");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2002-259");
 script_set_attribute(attribute: "description", value: '
  The sendmail packages shipped with Red Hat Linux Advanced Server have a
  security bug if sendmail is configured to use smrsh. This security errata
  release fixes the problem.

  [Updated 06 Feb 2003]
  Added fixed packages for Advanced Workstation 2.1

  SMRSH (the SendMail Restricted SHell) is a /bin/sh replacement for
  Sendmail. It provides the ability to limit the set of executable programs
  available to Sendmail.

  A bug in the version of smrsh packaged as part of Sendmail 8.12.6 and
  8.11.6 allows attackers to bypass shrsh\'s intended restrictions. This
  can be done by inserting additional commands after "||" or "/" characters,
  which are not properly filtered or verified. A sucessful attack would
  allow an attacker who has a local account on a system to execute arbitrary
  binaries as themselves by utilizing their .forward file.

  Because sendmail as shipped with Red Hat Linux Advanced Server is not
  configured to use smrsh, this issue only affects users who have customized
  their sendmail configuration to use smrsh.

  Users who have configured sendmail to use smrsh should update to these
  errata packages which contain a backported security fix, and are therefore
  not vulnerable to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2002-259.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2002-1165");
script_summary(english: "Check for the version of the sendmail packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"sendmail-8.11.6-9.72.4", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sendmail-cf-8.11.6-9.72.4", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sendmail-devel-8.11.6-9.72.4", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sendmail-doc-8.11.6-9.72.4", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
