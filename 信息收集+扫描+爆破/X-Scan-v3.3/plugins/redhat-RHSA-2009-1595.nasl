
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42850);
 script_version ("$Revision: 1.1 $");
 script_name(english: "RHSA-2009-1595: cups");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1595");
 script_set_attribute(attribute: "description", value: '
  Updated cups packages that fix multiple security issues are now available
  for Red Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The Common UNIX Printing System (CUPS) provides a portable printing layer
  for UNIX operating systems.

  A use-after-free flaw was found in the way CUPS handled references in its
  file descriptors-handling interface. A remote attacker could, in a
  specially-crafted way, query for the list of current print jobs for a
  specific printer, leading to a denial of service (cupsd crash).
  (CVE-2009-3553)

  Several cross-site scripting (XSS) flaws were found in the way the CUPS web
  server interface processed HTML form content. If a remote attacker could
  trick a local user who is logged into the CUPS web interface into visiting
  a specially-crafted HTML page, the attacker could retrieve and potentially
  modify confidential CUPS administration data. (CVE-2009-2820)

  Red Hat would like to thank Aaron Sigel of Apple Product Security for
  responsibly reporting the CVE-2009-2820 issue.

  Users of cups are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues. After installing the
  update, the cupsd daemon will be restarted automatically.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1595.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-2820", "CVE-2009-3553");
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

if ( rpm_check( reference:"cups-1.3.7-11.el5_4.4", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-devel-1.3.7-11.el5_4.4", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-libs-1.3.7-11.el5_4.4", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-lpd-1.3.7-11.el5_4.4", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
