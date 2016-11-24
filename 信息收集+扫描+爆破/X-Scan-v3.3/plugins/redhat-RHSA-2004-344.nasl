
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(14311);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2004-344: semi");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-344");
 script_set_attribute(attribute: "description", value: '
  Updated semi packages that fix vulnerabilities in flim temporary file
  handling are now available.

  The semi package includes a MIME library for GNU Emacs and XEmacs used by
  the wl mail package.

  Tatsuya Kinoshita discovered a vulnerability in flim, an emacs library
  for working with Internet messages included in the semi package. Temporary
  files were being created without taking adequate precautions, and therefore
  a local user could potentially overwrite files with the privileges of the
  user running emacs. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2004-0422 to this issue.

  Users of semi are advised to upgrade to these packages, which contain
  a backported patch fixing this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-344.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0422");
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

if ( rpm_check( reference:"semi-1.14.3-8.72.EL.1", release:'RHEL2.1') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"semi-xemacs-1.14.3-8.72.EL.1", release:'RHEL2.1') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
