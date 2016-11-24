
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(16371);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-136: mailman");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-136");
 script_set_attribute(attribute: "description", value: '
  Updated mailman packages that correct a mailman security issue are now
  available.

  The mailman package is software to help manage email discussion lists.

  A flaw in the true_path function of Mailman was discovered. A remote
  attacker who is a member of a private mailman list could use a carefully
  crafted URL and gain access to arbitrary files on the server. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2005-0202 to this issue.

  Note: Mailman installations running on Apache 2.0-based servers are not
  vulnerable to this issue.

  Users of mailman should update to these erratum packages that contain a
  patch and are not vulnerable to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-136.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-0202");
script_summary(english: "Check for the version of the mailman packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"mailman-2.0.13-7", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mailman-2.1.5-24.rhel3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
