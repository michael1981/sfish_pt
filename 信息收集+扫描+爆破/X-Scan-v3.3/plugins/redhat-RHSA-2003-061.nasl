
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12367);
 script_version ("$Revision: 1.8 $");
 script_name(english: "RHSA-2003-061: netpbm");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-061");
 script_set_attribute(attribute: "description", value: '
  Updated NetPBM packages are available that fix a number of vulnerabilities
  in the netpbm libraries.

  The netpbm package contains a library of functions that support
  programs for handling various graphics file formats, including .pbm
  (portable bitmaps), .pgm (portable graymaps), .pnm (portable anymaps),
  .ppm (portable pixmaps), and others.

  During an audit of the NetPBM library, Al Viro, Alan Cox, and Sebastian
  Krahmer found a number of bugs that are potentially exploitable. These
  bugs could be exploited by creating a carefully crafted image in such a way
  that it executes arbitrary code when it is processed by either an
  application from the netpbm-progs package or an application that uses the
  vulnerable netpbm library.

  One way that an attacker could exploit these vulnerabilities would be to
  submit a carefully crafted image to be printed, as the LPRng print spooler
  used by default in Red Hat Linux Advanced Products releases uses netpbm
  utilities to parse various types of image files.

  Users are advised to upgrade to the updated packages, which contain patches
  that correct these vulnerabilities.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-061.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0146");
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

if ( rpm_check( reference:"netpbm-9.24-9.AS21.2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"netpbm-devel-9.24-9.AS21.2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"netpbm-progs-9.24-9.AS21.2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
