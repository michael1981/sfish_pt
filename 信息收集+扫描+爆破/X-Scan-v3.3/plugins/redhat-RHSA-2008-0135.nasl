
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(31161);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0135: tk");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0135");
 script_set_attribute(attribute: "description", value: '
  Updated tk packages that fix a security issue are now available for Red Hat
  Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  [Updated 22 February 2008]
  The packages in this errata were originally pushed to the wrong Red Hat
  Network channels and were not available to all users. We have updated this
  errata with the correct channels.

  Tk is a graphical toolkit for the Tcl scripting language.

  An input validation flaw was discovered in Tk\'s GIF image handling. A
  code-size value read from a GIF image was not properly validated before
  being used, leading to a buffer overflow. A specially crafted GIF file
  could use this to cause a crash or, potentially, execute code with the
  privileges of the application using the Tk graphical toolkit.
  (CVE-2008-0553)

  A buffer overflow flaw was discovered in Tk\'s animated GIF image handling.
  An animated GIF containing an initial image smaller than subsequent images
  could cause a crash or, potentially, execute code with the privileges of
  the application using the Tk library. (CVE-2007-5378)

  All users are advised to upgrade to these updated packages which contain a
  backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0135.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-5378", "CVE-2008-0553");
script_summary(english: "Check for the version of the tk packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"tk-8.4.7-3.el4_6.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tk-devel-8.4.7-3.el4_6.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
