
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12323);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2002-191: gaim");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2002-191");
 script_set_attribute(attribute: "description", value: '
  Updated gaim packages are now available for Red Hat Linux Advanced Server.
  These updates fix a vulnerability in the default URL handler.

  Gaim is an all-in-one instant messaging client that lets you use a number
  of
  messaging protocols such as AIM, ICQ, and Yahoo, all at once.

  Versions of gaim prior to 0.59.1 contain a bug in the URL handler of
  the manual browser option. A link can be carefully crafted to contain
  an arbitrary shell script which will be executed if the user clicks on
  the link.

  Users of gaim should update to these errata packages containing gaim
  0.59.1 which is not vulnerable to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2002-191.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2002-0989");
script_summary(english: "Check for the version of the gaim packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gaim-0.59.1-0.2.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
