
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25752);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2007-0723: thunderbird");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0723");
 script_set_attribute(attribute: "description", value: '
  Updated thunderbird packages that fix several security bugs are now
  available for Red Hat Enterprise Linux 4 and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Mozilla Thunderbird is a standalone mail and newsgroup client.

  Several flaws were found in the way Thunderbird processed certain malformed
  JavaScript code. A malicious HTML email message containing JavaScript code
  could cause Thunderbird to crash or potentially execute arbitrary code as
  the user running Thunderbird. JavaScript support is disabled by default in
  Thunderbird; these issues are not exploitable unless the user has enabled
  JavaScript. (CVE-2007-3089, CVE-2007-3734, CVE-2007-3735, CVE-2007-3736,
  CVE-2007-3737, CVE-2007-3738)

  Users of Thunderbird are advised to upgrade to these erratum packages,
  which contain backported patches that correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0723.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-3089", "CVE-2007-3734", "CVE-2007-3735", "CVE-2007-3736", "CVE-2007-3737", "CVE-2007-3738");
script_summary(english: "Check for the version of the thunderbird packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"thunderbird-1.5.0.12-0.3.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"thunderbird-1.5.0.12-3.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
