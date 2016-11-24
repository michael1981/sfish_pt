
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-6271
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(33469);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 8 2008-6271: java-1.7.0-icedtea");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-6271 (java-1.7.0-icedtea)");
 script_set_attribute(attribute: "description", value: "The IcedTea runtime environment.

-
ChangeLog:


Update information :

* Wed Jul  2 2008 Lillian Angel <langel redhat com> - 1.7.0.0-0.20.b21.snapshot
- Added OpenJDK security patches.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the java-1.7.0-icedtea package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"java-1.7.0-icedtea-1.7.0.0-0.20.b21.snapshot.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
