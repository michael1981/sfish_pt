
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-3545
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(32205);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2008-3545: tkimg");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-3545 (tkimg)");
 script_set_attribute(attribute: "description", value: "This package contains a collection of image format handlers for the Tk
photo image type, and a new image type, pixmaps.
The provided format handlers include bmp, gif, ico, jpeg, pcx, png,
ppm, ps, sgi, sun, tga, tiff, xbm, and xpm.

-
References:

[ 1 ] Bug #431518 - CVE-2008-0553 tk: GIF handling buffer overflow
[9]https://bugzilla.redhat.com/show_bug.cgi?id=431518
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-0553");
script_summary(english: "Check for the version of the tkimg package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"tkimg-1.3-0.8.20080505svn.fc7", release:"FC7") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
