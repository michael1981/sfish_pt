
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-10718
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(42272);
 script_version("$Revision: 1.1 $");
script_name(english: "Fedora 11 2009-10718: sahana");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-10718 (sahana)");
 script_set_attribute(attribute: "description", value: "Sahana is a free and open source Disaster Management
System.It mainly facilitates management of Missing people,
disaster victims, Managing and administrating various
organisations, managing camps and managing requests and
assistance in the proper distribution of resources.

-
ChangeLog:


Update information :

* Wed Oct 21 2009 David Nalley <david gnsa us> 0.6.2.2-6
- fixed security issue noted in bz 530255
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the sahana package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"sahana-0.6.2.2-6.fc11", release:"FC11") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
