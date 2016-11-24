
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34428);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  MozillaThunderbird: Security fixes from 2.0.0.17 (MozillaThunderbird-5680)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch MozillaThunderbird-5680");
 script_set_attribute(attribute: "description", value: "This patch backports security fixes found in
MozillaThunderbird  2.0.0.17 back to the 1.5 Thunderbird
used in openSUSE 10.2.

MFSA 2008-34 / CVE-2008-2785: An anonymous researcher, via
TippingPoint's Zero Day Initiative program, reported a
vulnerability in Mozilla CSS reference counting code. The
vulnerability was caused by an insufficiently sized
variable being used as a reference counter for CSS objects.
By creating a very large number of references to a common
CSS object, this counter could be overflowed which could
cause a crash when the browser attempts to free the CSS
object while still in use. An attacker could use this crash
to run arbitrary code on the victim's computer
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch MozillaThunderbird-5680");
script_end_attributes();

script_cve_id("CVE-2008-2785");
script_summary(english: "Check for the MozillaThunderbird-5680 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"MozillaThunderbird-1.5.0.14-0.8", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"MozillaThunderbird-translations-1.5.0.14-0.8", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
