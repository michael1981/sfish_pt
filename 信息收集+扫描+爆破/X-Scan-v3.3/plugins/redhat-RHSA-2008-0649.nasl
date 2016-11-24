
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33784);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0649: libxslt");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0649");
 script_set_attribute(attribute: "description", value: '
  Updated libxslt packages that fix a security issue are now available for
  Red Hat Enterprise Linux 4 and Red Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  libxslt is a library for transforming XML files into other XML files using
  the standard XSLT stylesheet transformation mechanism.

  A heap buffer overflow flaw was discovered in the RC4 libxslt library
  extension. An attacker could create a malicious XSL file that would cause a
  crash, or, possibly, execute arbitrary code with the privileges of the
  application using the libxslt library to perform XSL transformations on
  untrusted XSL style sheets. (CVE-2008-2935)

  Red Hat would like to thank Chris Evans for reporting this vulnerability.

  All libxslt users are advised to upgrade to these updated packages, which
  contain a backported patch to resolve this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0649.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-2935");
script_summary(english: "Check for the version of the libxslt packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libxslt-1.1.17-2.el5_2.2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxslt-devel-1.1.17-2.el5_2.2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxslt-python-1.1.17-2.el5_2.2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxslt-1.1.11-1.el4_7.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxslt-devel-1.1.11-1.el4_7.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxslt-python-1.1.11-1.el4_7.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
