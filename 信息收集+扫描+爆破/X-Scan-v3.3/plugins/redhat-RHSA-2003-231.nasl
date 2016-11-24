
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12408);
 script_version ("$Revision: 1.8 $");
 script_name(english: "RHSA-2003-231: semi");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-231");
 script_set_attribute(attribute: "description", value: '
  Updated semi packages that fix vulnerabilities in semi\'s temporary file
  handling are now available.

  semi is a MIME library for GNU Emacs and XEmacs used by the wl mail
  package.

  A vulnerability in semi version 1.14.3 and earlier allows an attacker
  to overwrite arbitrary files with potentially arbitrary contents using the
  privileges of the user running Emacs and semi. The Common Vulnerabilities
  and Exposures project (cve.mitre.org) has assigned the name CAN-2003-0440
  to this issue.

  Users of semi are advised to upgrade to these packages, which contain
  a backported patch correcting this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-231.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0440");
script_summary(english: "Check for the version of the semi packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"semi-1.14.3-8.72.EL", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"semi-xemacs-1.14.3-8.72.EL", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
