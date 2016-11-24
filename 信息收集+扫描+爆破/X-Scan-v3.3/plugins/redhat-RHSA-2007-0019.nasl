
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(24259);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0019: gtk");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0019");
 script_set_attribute(attribute: "description", value: '
  Updated gtk2 packages that fix a security issue are now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The gtk2 package contains the GIMP ToolKit (GTK+), a library for creating
  graphical user interfaces for the X Window System.

  A bug was found in the way the gtk2 GdkPixbufLoader() function processed
  invalid input. Applications linked against gtk2 could crash if they
  loaded a malformed image file. (CVE-2007-0010)

  Users of gtk2 are advised to upgrade to these updated packages, which
  contain a backported patch to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0019.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-0010");
script_summary(english: "Check for the version of the gtk packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gtk2-2.4.13-22", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gtk2-devel-2.4.13-22", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
