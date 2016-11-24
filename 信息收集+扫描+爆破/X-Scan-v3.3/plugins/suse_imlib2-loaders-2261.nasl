
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29464);
 script_version ("$Revision: 1.6 $");
 script_name(english: "SuSE Security Update:  Security update for imlib2-loaders (imlib2-loaders-2261)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch imlib2-loaders-2261");
 script_set_attribute(attribute: "description", value: "Various security problems have been fixed in the imlib2
image loaders:

CVE-2006-4809: A stack buffer overflow in loader_pnm.c
could be used by attackers to execute code by supplying a
handcrafted PNM image.

CVE-2006-4808: A heap buffer overflow in loader_tga.c could
potentially be used by attackers to execute code by
supplying a handcrafted TGA image.

CVE-2006-4807: A out of bounds memory read in loader_tga.c
could be used to crash the imlib2 using application with a
handcrafted TGA image.

CVE-2006-4806: Various integer overflows in width*height
calculations could lead to heap overflows which could
potentially be used to execute code. Affected here are the
ARGB, PNG, LBM, JPEG and TIFF loaders.

Additionaly loading of TIFF images on 64bit systems now
works.

This obsoletes a previous update, which had broken JPEG
loading.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch imlib2-loaders-2261");
script_end_attributes();

script_cve_id("CVE-2006-4806", "CVE-2006-4807", "CVE-2006-4808", "CVE-2006-4809");
script_summary(english: "Check for the imlib2-loaders-2261 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"imlib2-loaders-1.2.1-17.9", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
