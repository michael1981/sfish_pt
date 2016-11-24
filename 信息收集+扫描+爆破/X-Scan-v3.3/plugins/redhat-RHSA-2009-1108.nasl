
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(39432);
 script_version ("$Revision: 1.3 $");
 script_name(english: "RHSA-2009-1108: httpd");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1108");
 script_set_attribute(attribute: "description", value: '
  Updated httpd packages that fix multiple security issues are now available
  for Red Hat Enterprise Linux 3.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The Apache HTTP Server is a popular Web server. The httpd package shipped
  with Red Hat Enterprise Linux 3 contains an embedded copy of the Apache
  Portable Runtime (APR) utility library, a free library of C data structures
  and routines, which includes interfaces to support XML parsing, LDAP
  connections, database interfaces, URI parsing, and more.

  An off-by-one overflow flaw was found in the way apr-util processed a
  variable list of arguments. An attacker could provide a specially-crafted
  string as input for the formatted output conversion routine, which could,
  on big-endian platforms, potentially lead to the disclosure of sensitive
  information or a denial of service (application crash). (CVE-2009-1956)

  Note: The CVE-2009-1956 flaw only affects big-endian platforms, such as the
  IBM S/390 and PowerPC. It does not affect users using the httpd package on
  little-endian platforms, due to their different organization of byte
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

  All httpd users should upgrade to these updated packages, which contain
  backported patches to correct these issues. After installing the updated
  packages, the httpd daemon must be restarted for the update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1108.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-0023", "CVE-2009-1955", "CVE-2009-1956");
script_summary(english: "Check for the version of the httpd packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"httpd-2.0.46-73.ent", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"httpd-devel-2.0.46-73.ent", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.0.46-73.ent", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
