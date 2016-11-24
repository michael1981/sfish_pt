
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-293
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24729);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 6 2007-293: gnome-python2-extras");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-293 (gnome-python2-extras)");
 script_set_attribute(attribute: "description", value: "The gnome-python-extra package contains the source packages for additional
Python bindings for GNOME. It should be used together with gnome-python.



Update information :

* Mon Feb 26 2007 Matthew Barnes <mbarnes redhat com> - 2.14.2-9.fc6
- Rebuild against firefox-1.5.0.10.

");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the gnome-python2-extras package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"gnome-python2-extras-2.14.2-9.fc6", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
