
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12474);
 script_version ("$Revision: 1.8 $");
 script_name(english: "RHSA-2004-090: libxml");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-090");
 script_set_attribute(attribute: "description", value: '
  Updated libxml2 packages that fix an overflow when parsing remote resources
  are now available.

  libxml2 is a library for manipulating XML files.

  Yuuichi Teranishi discovered a flaw in libxml2 versions prior to 2.6.6.
  When fetching a remote resource via FTP or HTTP, libxml2 uses special
  parsing routines. These routines can overflow a buffer if passed a very
  long URL. If an attacker is able to find an application using libxml2 that
  parses remote resources and allows them to influence the URL, then this
  flaw could be used to execute arbitrary code. The Common Vulnerabilities
  and Exposures project (cve.mitre.org) has assigned the name CAN-2004-0110
  to this issue.

  All users are advised to upgrade to these updated packages, which contain a
  backported fix and are not vulnerable to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-090.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0110");
script_summary(english: "Check for the version of the libxml packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libxml2-2.4.19-5.ent", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxml2-devel-2.4.19-5.ent", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxml2-python-2.4.19-5.ent", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxml2-2.5.10-6", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxml2-devel-2.5.10-6", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxml2-python-2.5.10-6", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
