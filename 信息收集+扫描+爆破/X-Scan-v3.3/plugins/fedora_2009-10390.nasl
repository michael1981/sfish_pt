
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-10390
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(42152);
 script_version("$Revision: 1.1 $");
script_name(english: "Fedora 11 2009-10390: Django");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-10390 (Django)");
 script_set_attribute(attribute: "description", value: "Django is a high-level Python Web framework that encourages rapid
development and a clean, pragmatic design. It focuses on automating as
much as possible and adhering to the DRY (Don't Repeat Yourself)
principle.

-
Update Information:

[9]http://www.djangoproject.com/weblog/2009/oct/09/security/      Description o
f
vulnerability  ============================  Django's forms library included
field types which perform regular-expression-based validation of email addresse
s
and URLs. Certain addresses/URLs could trigger a pathological performance case
in this regular expression, resulting in the server process/thread becoming
unresponsive, and consuming excessive CPU over an extended period of time. If
deliberately triggered, this could result in an effective denial-of-service
attack.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the Django package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"Django-1.1.1-1.fc11", release:"FC11") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
