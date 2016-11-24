
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(25309);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKA-2007:049: x11-server-xgl");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKA-2007:049 (x11-server-xgl).");
 script_set_attribute(attribute: "description", value: "The DPMS X server extension is responsible for managing the pwoer for
the display. It turns the display off (or puts it in standby mode)
after a programmed time of inactivity, however some applications can
disable DPMS' timers while running (such as a video player).
When using Xgl, the timers of the underlying servers were not properly
set, so if an application attempted to disable DPMS, it would still
be active. This update fixes the problem by forcing Xgl to always
configure the timers in the underlying server.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKA-2007:049");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_summary(english: "Check for the version of the x11-server-xgl package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"x11-server-xgl-0.0.1-0.20060714.11.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
