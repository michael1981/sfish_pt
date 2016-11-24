
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(32427);
 script_version ("$Revision: 1.3 $");
 script_name(english: "RHSA-2008-0485: compiz");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0485");
 script_set_attribute(attribute: "description", value: '
  Updated compiz packages that prevent Compiz from breaking screen saver
  grabs are now available for Red Hat Enterprise Linux 5.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  Compiz is an OpenGL-based window and compositing manager.

  Most screen savers create a top-level fullscreen window to cover the
  desktop, and grab the input with that window. Compiz has an option to
  un-redirect that window, but in some cases, this breaks the grab and
  compromises the locked screen. (CVE-2007-3920)

  Users of compiz are advised to upgrade to these updated packages, which
  remove this option to resolve this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0485.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-3920");
script_summary(english: "Check for the version of the compiz packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"compiz-0.0.13-0.37.20060817git.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
