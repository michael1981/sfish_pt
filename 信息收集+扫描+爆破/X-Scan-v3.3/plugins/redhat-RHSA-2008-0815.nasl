
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33892);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0815: yum");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0815");
 script_set_attribute(attribute: "description", value: '
  Updated yum-rhn-plugin packages that fix a security issue are now available
  for Red Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The yum-rhn-plugin provides support for yum to securely access a Red Hat
  Network (RHN) server for software updates.

  It was discovered that yum-rhn-plugin did not verify the SSL certificate
  for all communication with a Red Hat Network server. An attacker able to
  redirect the network communication between a victim and an RHN server could
  use this flaw to provide malicious repository metadata. This metadata could
  be used to block the victim from receiving specific security updates.
  (CVE-2008-3270)

  This flaw did not allow an attacker to install malicious packages. Package
  signatures were verified and only packages signed with a trusted Red Hat
  GPG key were installed.

  Red Hat would like to thank Justin Cappos and Justin Samuel for discussing
  various package update mechanism flaws which led to our discovery of this
  issue.

  Users of yum-rhn-plugin are advised to upgrade to this updated packages,
  which resolves this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0815.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-3270");
script_summary(english: "Check for the version of the yum packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"yum-rhn-plugin-0.5.3-12.el5_2.9", release:'RHEL5') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
