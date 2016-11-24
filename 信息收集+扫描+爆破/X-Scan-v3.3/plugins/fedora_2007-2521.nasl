
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-2521
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27775);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2007-2521: libpng10");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-2521 (libpng10)");
 script_set_attribute(attribute: "description", value: "The libpng10 package contains an old version of libpng, a library of functions
for creating and manipulating PNG (Portable Network Graphics) image format
files.

This package is needed if you want to run binaries that were linked dynamically
with libpng 1.0.x.

-
Update Information:

Certain chunk handlers in libpng10 before 1.0.29 allow remote attackers to caus
e a denial of service (crash) via crafted (1) pCAL (png_handle_pCAL), (2) sCAL
(png_handle_sCAL), (3) tEXt (png_push_read_tEXt), (4) iTXt (png_handle_iTXt), a
nd (5) ztXT (png_handle_ztXt) chunking in PNG images, which trigger out-of-boun
ds read operations.

[9]http://secunia.com/advisories/27093
[10]http://www.frsirt.com/english/advisories/2007/3390
[11]http://sourceforge.net/mailarchive/forum.php?thread_name=3.0.6.32.200710040
82318.012a7628%40mail.comcast.net&forum_name=png-mng-implement

This update to 1.0.29 addresses these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-2445", "CVE-2007-5269");
script_summary(english: "Check for the version of the libpng10 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"libpng10-1.0.29-1.fc7", release:"FC7") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
