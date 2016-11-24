
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(39431);
 script_version ("$Revision: 1.3 $");
 script_name(english: "RHSA-2009-1107: apr");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1107");
 script_set_attribute(attribute: "description", value: '
  Updated apr-util packages that fix multiple security issues are now
  available for Red Hat Enterprise Linux 4 and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  apr-util is a utility library used with the Apache Portable Runtime (APR).
  It aims to provide a free library of C data structures and routines. This
  library contains additional utility interfaces for APR; including support
  for XML, LDAP, database interfaces, URI parsing, and more.

  An off-by-one overflow flaw was found in the way apr-util processed a
  variable list of arguments. An attacker could provide a specially-crafted
  string as input for the formatted output conversion routine, which could,
  on big-endian platforms, potentially lead to the disclosure of sensitive
  information or a denial of service (application crash). (CVE-2009-1956)

  Note: The CVE-2009-1956 flaw only affects big-endian platforms, such as the
  IBM S/390 and PowerPC. It does not affect users using the apr-util package
  on little-endian platforms, due to their different organization of byte
  ordering used to represent particular data.

  A denial of service flaw was found in the apr-util Extensible Markup
  Language (XML) parser. A remote attacker could create a specially-crafted
  XML document that would cause excessive memory consumption when processed
  by the XML decoding engine. (CVE-2009-1955)

  A heap-based underwrite flaw was found in the way apr-util created compiled
  forms of particular search patterns. An attacker could formulate a
  specially-crafted search keyword, that would overwrite arbitrary heap
  memory locations when processed by the pattern preparation engine.
  (CVE-2009-0023)

  All apr-util users should upgrade to these updated packages, which contain
  backported patches to correct these issues. Applications using the Apache
  Portable Runtime library, such as httpd, must be restarted for this update
  to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1107.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-0023", "CVE-2009-1955", "CVE-2009-1956");
script_summary(english: "Check for the version of the apr packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"apr-util-1.2.7-7.el5_3.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-util-devel-1.2.7-7.el5_3.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-util-docs-1.2.7-7.el5_3.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-util-0.9.4-22.el4_8.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-util-devel-0.9.4-22.el4_8.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-util-0.9.4-22.el4_8.1", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-util-devel-0.9.4-22.el4_8.1", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-util-1.2.7-7.el5_3.1", release:'RHEL5.3.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-util-devel-1.2.7-7.el5_3.1", release:'RHEL5.3.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apr-util-docs-1.2.7-7.el5_3.1", release:'RHEL5.3.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
