
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(36178);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2009-0428: cups");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0428");
 script_set_attribute(attribute: "description", value: '
  Updated cups packages that fix one security issue are now available for Red
  Hat Enterprise Linux 3.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The Common UNIX® Printing System (CUPS) provides a portable printing layer
  for UNIX operating systems.

  An integer overflow flaw, leading to a heap-based buffer overflow, was
  discovered in the Tagged Image File Format (TIFF) decoding routines used by
  the CUPS image-converting filters, "imagetops" and "imagetoraster". An
  attacker could create a malicious TIFF file that could, potentially,
  execute arbitrary code as the "lp" user if the file was printed.
  (CVE-2009-0163)

  Red Hat would like to thank Aaron Sigel of the Apple Product Security team
  for responsibly reporting this flaw.

  Users of cups are advised to upgrade to these updated packages, which
  contain a backported patch to correct this issue. After installing the
  update, the cupsd daemon will be restarted automatically.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0428.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-0163");
script_summary(english: "Check for the version of the cups packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"cups-1.1.17-13.3.58", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-devel-1.1.17-13.3.58", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-libs-1.1.17-13.3.58", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
