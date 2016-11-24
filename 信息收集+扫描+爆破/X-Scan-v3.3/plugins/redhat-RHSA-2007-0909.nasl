
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(26952);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0909: kdelibs");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0909");
 script_set_attribute(attribute: "description", value: '
  Updated kdelibs packages that resolve several security flaws are
  now available for Red Hat Enterprise Linux 4 and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The kdelibs package provides libraries for the K Desktop Environment (KDE).

  Two cross-site-scripting flaws were found in the way Konqueror processes
  certain HTML content. This could result in a malicious attacker presenting
  misleading content to an unsuspecting user. (CVE-2007-0242, CVE-2007-0537)

  A flaw was found in KDE JavaScript implementation. A web page containing
  malicious JavaScript code could cause Konqueror to crash. (CVE-2007-1308)

  A flaw was found in the way Konqueror handled certain FTP PASV commands.
  A malicious FTP server could use this flaw to perform a rudimentary
  port-scan of machines behind a user\'s firewall. (CVE-2007-1564)

  Two Konqueror address spoofing flaws have been discovered. It was
  possible for a malicious website to cause the Konqueror address bar to
  display information which could trick a user into believing they are at a
  different website than they actually are. (CVE-2007-3820, CVE-2007-4224)

  Users of KDE should upgrade to these updated packages, which contain
  backported patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0909.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-0242", "CVE-2007-0537", "CVE-2007-1308", "CVE-2007-1564", "CVE-2007-3820", "CVE-2007-4224");
script_summary(english: "Check for the version of the kdelibs packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"kdelibs-3.5.4-13.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdelibs-apidocs-3.5.4-13.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdelibs-devel-3.5.4-13.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdelibs-3.3.1-9.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdelibs-devel-3.3.1-9.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
