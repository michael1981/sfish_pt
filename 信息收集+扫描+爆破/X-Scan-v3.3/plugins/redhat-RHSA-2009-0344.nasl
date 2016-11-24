
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35944);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2009-0344: libsoup");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0344");
 script_set_attribute(attribute: "description", value: '
  Updated libsoup and evolution28-libsoup packages that fix a security issue
  are now available for Red Hat Enterprise Linux 4 and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  libsoup is an HTTP client/library implementation for GNOME written in C. It
  was originally part of a SOAP (Simple Object Access Protocol)
  implementation called Soup, but the SOAP and non-SOAP parts have now been
  split into separate packages.

  An integer overflow flaw which caused a heap-based buffer overflow was
  discovered in libsoup\'s Base64 encoding routine. An attacker could use this
  flaw to crash, or, possibly, execute arbitrary code. This arbitrary code
  would execute with the privileges of the application using libsoup\'s Base64
  routine to encode large, untrusted inputs. (CVE-2009-0585)

  All users of libsoup and evolution28-libsoup should upgrade to these
  updated packages, which contain a backported patch to resolve this issue.
  All running applications using the affected library function (such as
  Evolution configured to connect to the GroupWise back-end) must be
  restarted for the update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0344.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-0585");
script_summary(english: "Check for the version of the libsoup packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libsoup-2.2.98-2.el5_3.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libsoup-devel-2.2.98-2.el5_3.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"evolution28-libsoup-2.2.98-5.el4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"evolution28-libsoup-devel-2.2.98-5.el4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libsoup-2.2.1-4.el4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libsoup-devel-2.2.1-4.el4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
