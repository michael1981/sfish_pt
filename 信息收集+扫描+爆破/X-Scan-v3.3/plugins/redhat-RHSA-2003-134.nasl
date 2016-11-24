
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12386);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2003-134: man");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-134");
 script_set_attribute(attribute: "description", value: '
  Updated man packages fix a minor security vulnerability.

  The man package includes tools for finding information and documentation
  about commands on a system.

  Versions of man before 1.51 have a bug where a malformed man file can cause
  a program named "unsafe" to be run. To exploit this vulnerability a local
  attacker would need to be able to get a victim to run man on a carefully
  crafted man file, and for the attacker to be able to create a file called
  "unsafe" that will be on the victim\'s default path.

  Users of man can upgrade to these erratum packages which contain a patch to
  correct this vulnerability. These erratum packages also contain fixes for
  a number of other bugs.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-134.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0124");
script_summary(english: "Check for the version of the man packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"man-1.5i2-7.21as.0", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
