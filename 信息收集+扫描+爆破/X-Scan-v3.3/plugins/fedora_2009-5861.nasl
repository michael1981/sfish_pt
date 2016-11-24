
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-5861
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(39395);
 script_version ("$Revision: 1.1 $");
script_name(english: "Fedora 10 2009-5861: gupnp");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-5861 (gupnp)");
 script_set_attribute(attribute: "description", value: "GUPnP is an object-oriented open source framework for creating UPnP
devices and control points, written in C using GObject and libsoup.
The GUPnP API is intended to be easy to use, efficient and flexible.

-
Update Information:

New upstream release that fixes a bug where the gupnp stack crashes when passed
empty content    ChangeLog here  [9]http://git.gupnp.org/cgit.cgi?url=gupnp/tre
e/NE
WS&id=ce714a6700ce03953a2886a66ec57db59205f4e6    Bug report here
[10]http://bugzilla.openedhand.com/show_bug.cgi?id=1604    Other bugs fixed her
e.  -
bug#1570: gupnp doesn't set the pkgconfig lib dir correctly in 64 bit env.  -
bug#1574: Avoid using asserts.  - bug#1592: gupnp_device_info_get_icon_url()
does not return the closest match.  - bug#1604: Crash on action without any
content.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the gupnp package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"gupnp-0.12.8-1.fc10", release:"FC10") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
