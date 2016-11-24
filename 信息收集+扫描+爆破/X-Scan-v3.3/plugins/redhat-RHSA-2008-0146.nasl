
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(31306);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0146: gd");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0146");
 script_set_attribute(attribute: "description", value: '
  Updated gd packages that fix multiple security issues are now available for
  Red Hat Enterprise Linux 4 and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The gd package contains a graphics library used for the dynamic creation of
  images such as PNG and JPEG.

  Multiple issues were discovered in the gd GIF image-handling code. A
  carefully-crafted GIF file could cause a crash or possibly execute code
  with the privileges of the application using the gd library.
  (CVE-2006-4484, CVE-2007-3475, CVE-2007-3476)

  An integer overflow was discovered in the gdImageCreateTrueColor()
  function, leading to incorrect memory allocations. A carefully crafted
  image could cause a crash or possibly execute code with the privileges of
  the application using the gd library. (CVE-2007-3472)

  A buffer over-read flaw was discovered. This could cause a crash in an
  application using the gd library to render certain strings using a
  JIS-encoded font. (CVE-2007-0455)

  A flaw was discovered in the gd PNG image handling code. A truncated PNG
  image could cause an infinite loop in an application using the gd library.
  (CVE-2007-2756)

  A flaw was discovered in the gd X BitMap (XBM) image-handling code. A
  malformed or truncated XBM image could cause a crash in an application
  using the gd library. (CVE-2007-3473)

  Users of gd should upgrade to these updated packages, which contain
  backported patches which resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0146.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-4484", "CVE-2007-0455", "CVE-2007-2756", "CVE-2007-3472", "CVE-2007-3473", "CVE-2007-3475", "CVE-2007-3476");
script_summary(english: "Check for the version of the gd packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gd-2.0.33-9.4.el5_1.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gd-devel-2.0.33-9.4.el5_1.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gd-progs-2.0.33-9.4.el5_1.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gd-2.0.28-5.4E.el4_6.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gd-devel-2.0.28-5.4E.el4_6.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gd-progs-2.0.28-5.4E.el4_6.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
