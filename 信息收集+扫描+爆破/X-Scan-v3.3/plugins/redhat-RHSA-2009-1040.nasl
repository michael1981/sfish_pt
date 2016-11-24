
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(38821);
 script_version ("$Revision: 1.3 $");
 script_name(english: "RHSA-2009-1040: ntp");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1040");
 script_set_attribute(attribute: "description", value: '
  An updated ntp package that fixes two security issues is now available for
  Red Hat Enterprise Linux 4.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  The Network Time Protocol (NTP) is used to synchronize a computer\'s time
  with a referenced time source.

  A buffer overflow flaw was discovered in the ntpd daemon\'s NTPv4
  authentication code. If ntpd was configured to use public key cryptography
  for NTP packet authentication, a remote attacker could use this flaw to
  send a specially-crafted request packet that could crash ntpd or,
  potentially, execute arbitrary code with the privileges of the "ntp" user.
  (CVE-2009-1252)

  Note: NTP authentication is not enabled by default.

  A buffer overflow flaw was found in the ntpq diagnostic command. A
  malicious, remote server could send a specially-crafted reply to an ntpq
  request that could crash ntpq or, potentially, execute arbitrary code with
  the privileges of the user running the ntpq command. (CVE-2009-0159)

  All ntp users are advised to upgrade to this updated package, which
  contains backported patches to resolve these issues. After installing the
  update, the ntpd daemon will be restarted automatically.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1040.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-0159", "CVE-2009-1252");
script_summary(english: "Check for the version of the ntp packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"ntp-4.2.0.a.20040617-8.el4_7.2", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ntp-4.2.0.a.20040617-8.el4_7.2", release:'RHEL4.7.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ntp-4.2.0.a.20040617-8.el4_7.2", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
