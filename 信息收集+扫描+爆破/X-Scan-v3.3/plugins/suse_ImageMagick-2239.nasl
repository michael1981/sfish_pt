
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29348);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  Security update for ImageMagick (ImageMagick-2239)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch ImageMagick-2239");
 script_set_attribute(attribute: "description", value: "Two security problems were found in GraphicsMagick which
are also present in ImageMagick.

CVE-2006-5456: Multiple buffer overflows in ImageMagick
allowed user-assisted attackers to cause a denial of
service and possibly execute execute arbitrary code via (1)
a DCM image that is not properly handled by the
ReadDCMImage function in coders/dcm.c, or (2) a PALM image
that is not properly handled by the ReadPALMImage function
in coders/palm.c.

Additionaly a segfault regression when converting a PGM
image was fixed on SLE 10.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch ImageMagick-2239");
script_end_attributes();

script_cve_id("CVE-2006-5456");
script_summary(english: "Check for the ImageMagick-2239 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"ImageMagick-6.2.5-16.10", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ImageMagick-Magick++-6.2.5-16.10", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ImageMagick-devel-6.2.5-16.10", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
