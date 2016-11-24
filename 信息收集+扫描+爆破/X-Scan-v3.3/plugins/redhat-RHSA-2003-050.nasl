
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12363);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2003-050: kon");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-050");
 script_set_attribute(attribute: "description", value: '
  A buffer overflow in kon2 allows local users to obtain root privileges.

  KON is a Kanji emulator for the console. There is a buffer overflow
  vulnerability in the command line parsing code portion of the kon program
  up to and including version 0.3.9b. This vulnerability, if appropriately
  exploited, can lead to local users being able to gain escalated (root)
  privileges.

  All users of kon2 should update to these errata packages which contain a
  patch to fix this vulnerability.

  Red Hat would like to thank Janusz Niewiadomski for notifying us of this
  issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-050.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2002-1155");
script_summary(english: "Check for the version of the kon packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"kon2-0.3.9b-14.as21.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kon2-fonts-0.3.9b-14.as21.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
