
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12411);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2003-242: ddskk");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-242");
 script_set_attribute(attribute: "description", value: '
  Updated ddskk packages which fix a temporary file security issue are now
  available.

  Daredevil SKK is a simple Kana to Kanji conversion program, an input method
  of Japanese for Emacs.

  ddskk does not take appropriate security precautions when creating
  temporary files. This bug could potentially be exploited to overwrite
  arbitrary files with the privileges of the user running Emacs and skk. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has allocated
  the name CAN-2003-0539 to this issue.

  All users of ddskk should upgrade to these erratum packages containing a
  backported security patch that corrects this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-242.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0539");
script_summary(english: "Check for the version of the ddskk packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"ddskk-11.6.0-1.7.ent", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
