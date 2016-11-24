
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29347);
 script_version ("$Revision: 1.6 $");
 script_name(english: "SuSE Security Update:  Security update for ImageMagick (ImageMagick-2048)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch ImageMagick-2048");
 script_set_attribute(attribute: "description", value: "Several security problems have been fixed in ImageMagick:

- CVE-2006-3744: Several heap buffer overflow were found in
  the Sun Bitmap decoder of ImageMagick by an audit by the
  Google Security Team. This problem could be exploited by
  an attacker to execute code.

- CVE-2006-3743: Multiple buffer overflows were found in
  the XCF plugin due to incorrect bounds checking by the
  Google Security Team. This problem could be exploited by
  an attacker to execute code.

- CVE-2006-4144: A integer overflow in the ReadSGIImage
  function can be used by attackers to potentially execute
  code.

- An infinite loop in ImageMagick caused by TransformHSB
  was fixed.

- An infinite loop in handling of TIFF images was fixed.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch ImageMagick-2048");
script_end_attributes();

script_cve_id("CVE-2006-3743", "CVE-2006-3744", "CVE-2006-4144");
script_summary(english: "Check for the ImageMagick-2048 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"ImageMagick-6.2.5-16.5", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ImageMagick-Magick++-6.2.5-16.5", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ImageMagick-devel-6.2.5-16.5", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
