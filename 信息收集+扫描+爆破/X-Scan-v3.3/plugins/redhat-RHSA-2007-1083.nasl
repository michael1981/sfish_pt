
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29773);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2007-1083: thunderbird");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-1083");
 script_set_attribute(attribute: "description", value: '
  Updated thunderbird packages that fix several security issues are now
  available for Red Hat Enterprise Linux 4 and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Mozilla Thunderbird is a standalone mail and newsgroup client.

  A cross-site scripting flaw was found in the way Thunderbird handled the
  jar: URI scheme. It may be possible for a malicious HTML mail message to
  leverage this flaw, and conduct a cross-site scripting attack against a
  user running Thunderbird. (CVE-2007-5947)

  Several flaws were found in the way Thunderbird processed certain malformed
  HTML mail content. A HTML mail message containing malicious content could
  cause Thunderbird to crash, or potentially execute arbitrary code as the
  user running Thunderbird. (CVE-2007-5959)

  A race condition existed when Thunderbird set the "window.location"
  property when displaying HTML mail content. This flaw could allow a HTML
  mail message to set an arbitrary Referer header, which may lead to a
  Cross-site Request Forgery (CSRF) attack against websites that rely only on
  the Referer header for protection. (CVE-2007-5960)

  All users of thunderbird are advised to upgrade to these updated packages,
  which contain backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-1083.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-5947", "CVE-2007-5959", "CVE-2007-5960");
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

if ( rpm_check( reference:"thunderbird-1.5.0.12-7.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"thunderbird-1.5.0.12-7.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
