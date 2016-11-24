
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35551);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2009-0046: ntp");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0046");
 script_set_attribute(attribute: "description", value: '
  Updated ntp packages to correct a security issue are now available for Red
  Hat Enterprise Linux 4 and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The Network Time Protocol (NTP) is used to synchronize a computer\'s time
  with a referenced time source.

  A flaw was discovered in the way the ntpd daemon checked the return value
  of the OpenSSL EVP_VerifyFinal function. On systems using NTPv4
  authentication, this could lead to an incorrect verification of
  cryptographic signatures, allowing time-spoofing attacks. (CVE-2009-0021)

  Note: This issue only affects systems that have enabled NTP authentication.
  By default, NTP authentication is not enabled.

  All ntp users are advised to upgrade to the updated packages, which contain
  a backported patch to resolve this issue. After installing the update, the
  ntpd daemon will restart automatically.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0046.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-0021");
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

if ( rpm_check( reference:"ntp-4.2.2p1-9.el5_3.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ntp-4.2.0.a.20040617-8.el4_7.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
