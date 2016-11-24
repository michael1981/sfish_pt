
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(31305);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0131: netpbm");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0131");
 script_set_attribute(attribute: "description", value: '
  Updated netpbm packages that fix a security issue are now available for Red
  Hat Enterprise Linux 2.1, 3, and 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The netpbm package contains a library of functions for editing and
  converting between various graphics file formats, including .pbm (portable
  bitmaps), .pgm (portable graymaps), .pnm (portable anymaps), .ppm (portable
  pixmaps) and others. The package includes no interactive tools and is
  primarily used by other programs (eg CGI scripts that manage web-site
  images).

  An input validation flaw was discovered in the GIF-to-PNM converter
  (giftopnm) shipped with the netpbm package. An attacker could create a
  carefully crafted GIF file which could cause giftopnm to crash or possibly
  execute arbitrary code as the user running giftopnm. (CVE-2008-0554)

  All users are advised to upgrade to these updated packages which contain a
  backported patch which resolves this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0131.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-0554");
script_summary(english: "Check for the version of the netpbm packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"netpbm-9.24-9.AS21.7", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"netpbm-devel-9.24-9.AS21.7", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"netpbm-progs-9.24-9.AS21.7", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"netpbm-9.24-11.30.5", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"netpbm-devel-9.24-11.30.5", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"netpbm-progs-9.24-11.30.5", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"netpbm-10.25-2.EL4.6.el4_6.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"netpbm-devel-10.25-2.EL4.6.el4_6.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"netpbm-progs-10.25-2.EL4.6.el4_6.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
