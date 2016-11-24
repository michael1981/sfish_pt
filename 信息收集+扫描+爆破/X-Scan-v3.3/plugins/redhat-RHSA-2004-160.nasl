
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12487);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2004-160: openoffice.org");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-160");
 script_set_attribute(attribute: "description", value: '
  Updated OpenOffice packages that fix a vulnerability in neon exploitable by
  a malicious DAV server are now available.

  OpenOffice.org is an Open Source, community-developed, multi-platform
  office productivity suite. OpenOffice internally uses inbuilt code
  from neon, an HTTP and WebDAV client library.

  Versions of the neon client library up to and including 0.24.4 have been
  found to contain a number of format string bugs. An attacker could create
  a malicious WebDAV server in such a way as to allow arbitrary code
  execution on the client should a user connect to it using OpenOffice. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CAN-2004-0179 to this issue.

  Users of OpenOffice are advised to upgrade to these updated packages, which
  contain a patch correcting this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-160.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0179");
script_summary(english: "Check for the version of the openoffice.org packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"openoffice.org-1.1.0-15.EL", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-i18n-1.1.0-15.EL", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-libs-1.1.0-15.EL", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
