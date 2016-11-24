
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(16149);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-018: xpdf");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-018");
 script_set_attribute(attribute: "description", value: '
  Updated Xpdf packages that fix several security issues are now available.

  Xpdf is an X Window System based viewer for Portable Document Format (PDF)
  files.

  A buffer overflow flaw was found in the Gfx::doImage function of Xpdf. An
  attacker could construct a carefully crafted PDF file that could cause Xpdf
  to crash or possibly execute arbitrary code when opened. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2004-1125 to this issue.

  Red Hat believes that the Exec-Shield technology (enabled by default since
  Update 3) will block attempts to exploit this vulnerability on x86
  architectures.

  All users of the Xpdf packages should upgrade to these updated packages,
  which resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-018.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-1125");
script_summary(english: "Check for the version of the xpdf packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"xpdf-2.02-9.4", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
