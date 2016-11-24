
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(17979);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-340: curl");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-340");
 script_set_attribute(attribute: "description", value: '
  Updated curl packages are now available.

  This update has been rated as having low security impact by the
  Red Hat Security Response Team.

  cURL is a tool for getting files from FTP, HTTP, Gopher, Telnet, and
  Dict servers, using any of the supported protocols. cURL is designed
  to work without user interaction or any kind of interactivity.

  Multiple buffer overflow bugs were found in the way curl processes base64
  encoded replies. If a victim can be tricked into visiting a URL with curl,
  a malicious web server could execute arbitrary code on a victim\'s machine.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CAN-2005-0490 to this issue.

  All users of curl are advised to upgrade to these updated
  packages, which contain backported fixes for these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-340.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-0490");
script_summary(english: "Check for the version of the curl packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"curl-7.8-2.rhel2", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"curl-devel-7.8-2.rhel2", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"curl-7.10.6-6.rhel3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"curl-devel-7.10.6-6.rhel3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"curl-7.12.1-5.rhel4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"curl-devel-7.12.1-5.rhel4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
