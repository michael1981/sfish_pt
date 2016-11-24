
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-9911
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(42045);
 script_version ("$Revision: 1.1 $");
script_name(english: "Fedora 11 2009-9911: sunbird");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-9911 (sunbird)");
 script_set_attribute(attribute: "description", value: "Mozilla Sunbird is a cross-platform calendar application, built upon
Mozilla Toolkit. It brings Mozilla-style ease-of-use to your
calendar, without tying you to a particular storage solution.

-
ChangeLog:


Update information :

* Tue Sep 22 2009 Jan Horak <jhorak redhat com> - 1.0-0.7.20090715hg
- Sync up with Thunderbird
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the sunbird package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"sunbird-1.0-0.7.20090715hg.fc11", release:"FC11") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
