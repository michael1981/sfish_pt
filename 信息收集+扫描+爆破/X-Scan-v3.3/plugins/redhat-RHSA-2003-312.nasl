
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12429);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2003-312: pan");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-312");
 script_set_attribute(attribute: "description", value: '
  Updated Pan packages that close a denial of service vulnerability are now
  available.

  Pan is a Gnome/GTK+ newsreader.

  A bug in Pan versions prior to 0.13.4 can cause Pan to crash when parsing
  an article header containing a very long author email address. This bug
  causes a denial of service (crash), but cannot be exploited further. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CAN-2003-0855 to this issue.

  Users of Pan are advised to upgrade to these erratum packages, which
  contain a backported patch correcting this issue.

  Red Hat would like to thank Kasper Dupont for alerting us to this issue and
  to Charles Kerr for providing the patch.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-312.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0855");
script_summary(english: "Check for the version of the pan packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"pan-0.9.7-3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
