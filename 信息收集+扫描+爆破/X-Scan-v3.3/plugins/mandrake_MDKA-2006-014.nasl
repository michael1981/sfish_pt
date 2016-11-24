
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24498);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKA-2006:014: dynamic");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKA-2006:014 (dynamic).");
 script_set_attribute(attribute: "description", value: "Dynamic was not calling scripts correctly when hardware was
plugged/unplugged. Plugging a digital camera (not usb mass storage,
like a Canon camera) was not creating an icon on Desktop (for GNOME)
or in the Devices window (for KDE).
Dynamic was also creating a 'pilot' symlink in / (in addition to
/dev/pilot) when a Palm was connected, and this file was not removed
when the Palm was unplugged. Now, this file is not longer created.
If the symlink is already on the user's system, it can safely be
removed manually.
Updated packages have been patched to correct the issue.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKA-2006:014");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_summary(english: "Check for the version of the dynamic package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"dynamic-0.26.2-1.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
