
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(20364);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2005-875: curl");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-875");
 script_set_attribute(attribute: "description", value: '
  Updated curl packages that fix a security issue are now available for Red
  Hat Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  cURL is a tool for getting files from FTP, HTTP, Gopher, Telnet, and Dict
  servers, using any of the supported protocols.

  Stefan Esser discovered an off-by-one bug in curl. It may be possible to
  execute arbitrary code on a user\'s machine if the user can be tricked into
  executing curl with a carefully crafted URL. The Common Vulnerabilities and
  Exposures project assigned the name CVE-2005-4077 to this issue.

  All users of curl are advised to upgrade to these updated packages, which
  contain a backported patch that resolves this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-875.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-4077");
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

if ( rpm_check( reference:"curl-7.12.1-8.rhel4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"curl-devel-7.12.1-8.rhel4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
