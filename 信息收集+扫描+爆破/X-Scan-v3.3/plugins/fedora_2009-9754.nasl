
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-9754
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(41020);
 script_version ("$Revision: 1.1 $");
script_name(english: "Fedora 10 2009-9754: drupal-date");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-9754 (drupal-date)");
 script_set_attribute(attribute: "description", value: "The Date API is available to be used by other modules and is not dependent
on having CCK installed.  The date module is a flexible date/time field
type for the cck content module which requires the CCK content.module and
the Date API module.

-
Update Information:


Update information :

* Advisory ID: DRUPAL-SA-CONTRIB-2009-057     ( [9]http://drupal.org/node/5791
44 )
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the drupal-date package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"drupal-date-6.x.2.4-0.fc10", release:"FC10") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
