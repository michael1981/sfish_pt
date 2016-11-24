
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25327);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2007-0158: evolution");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0158");
 script_set_attribute(attribute: "description", value: '
  Updated evolution packages that fix a format string bug are now available
  for Red Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Evolution is the GNOME collection of personal information management (PIM)
  tools.

  A format string bug was found in the way Evolution parsed the category field
  in a memo. If a user tried to save and then view a carefully crafted memo,
  arbitrary code may be executed as the user running Evolution. (CVE-2007-1002)

  This flaw did not affect the versions of Evolution shipped with Red Hat
  Enterprise Linux 2.1, 3, or 4.

  All users of Evolution should upgrade to these updated packages, which
  contain a backported patch which resolves this issue.

  Red Hat would like to thank Ulf H  rnhammar of Secunia Research for
  reporting this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0158.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-1002");
script_summary(english: "Check for the version of the evolution packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"evolution-2.8.0-33.0.1.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
