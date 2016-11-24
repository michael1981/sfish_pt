
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25312);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2007-0055: libwpd");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0055");
 script_set_attribute(attribute: "description", value: '
  Updated libwpd packages to correct a security issue are now available for
  Red Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  libwpd is a library for reading and converting Word Perfect documents.

  iDefense reported several overflow bugs in libwpd. An attacker could
  create a carefully crafted Word Perfect file that could cause an
  application linked with libwpd, such as OpenOffice, to crash or possibly
  execute arbitrary code if the file was opened by a victim. (CVE-2007-0002)

  All users are advised to upgrade to these updated packages, which contain a
  backported fix for this issue.

  Red Hat would like to thank Fridrich   trba for alerting us to these issues
  and providing a patch.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0055.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-0002", "CVE-2007-1466");
script_summary(english: "Check for the version of the libwpd packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libwpd-0.8.7-3.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libwpd-tools-0.8.7-3.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
