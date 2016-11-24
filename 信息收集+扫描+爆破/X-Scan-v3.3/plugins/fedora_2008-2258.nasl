
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-2258
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(31370);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 8 2008-2258: nx");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-2258 (nx)");
 script_set_attribute(attribute: "description", value: "NX provides a proxy system for the X Window System.

-
ChangeLog:


Update information :

* Wed Jan  2 2008 Axel Thimm <Axel Thimm ATrpms net> - 3.1.0-25
- Update to 3.1.0.
- add nxcompshad, nxauth; remove nxviewer, nxdesktop.
- add -fPIC for ppc64.
- Propagate %{optflags} for x86_64, too.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the nx package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"nx-3.1.0-25.1.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
