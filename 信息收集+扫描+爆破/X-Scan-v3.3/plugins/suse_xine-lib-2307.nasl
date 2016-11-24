
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29598);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  Security update for xine-lib (xine-lib-2307)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch xine-lib-2307");
 script_set_attribute(attribute: "description", value: "Multiple buffer overflows were fixed in the XINE decoder
libraries, which could be used by attackers to crash
players or potentially execute code.


CVE-2006-4799: Buffer overflow in ffmpeg for xine-lib
before 1.1.2 might allow context-dependent attackers to
execute arbitrary code via a crafted AVI file and 'bad
indexes'.

CVE-2006-4800: Multiple buffer overflows in libavcodec in
ffmpeg before 0.4.9_p20060530 allow remote attackers to
cause a denial of service or possibly execute arbitrary
code via multiple unspecified vectors in (1) dtsdec.c, (2)
vorbis.c, (3) rm.c, (4) sierravmd.c, (5) smacker.c, (6)
tta.c, (7) 4xm.c, (8) alac.c, (9) cook.c, (10) shorten.c,
(11) smacker.c, (12) snow.c, and (13) tta.c.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch xine-lib-2307");
script_end_attributes();

script_cve_id("CVE-2006-4799", "CVE-2006-4800");
script_summary(english: "Check for the xine-lib-2307 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"xine-lib-1.1.1-24.10", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
