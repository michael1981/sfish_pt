
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(19297);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-640: fetchmail");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-640");
 script_set_attribute(attribute: "description", value: '
  Updated fetchmail packages that fix a security flaw are now available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  Fetchmail is a remote mail retrieval and forwarding utility.

  A buffer overflow was discovered in fetchmail\'s POP3 client. A malicious
  server could cause send a carefully crafted message UID and cause fetchmail
  to crash or potentially execute arbitrary code as the user running
  fetchmail. The Common Vulnerabilities and Exposures project assigned the
  name CAN-2005-2335 to this issue.

  Users of fetchmail should update to this erratum package which contains a
  backported patch to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-640.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-2335");
script_summary(english: "Check for the version of the fetchmail packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"fetchmail-5.9.0-21.7.3.el2.1.1", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-5.9.0-21.7.3.el2.1.1", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmail-6.2.0-3.el3.2", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmail-6.2.5-6.el4.2", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
