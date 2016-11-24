
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-2869
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36320);
 script_version ("$Revision: 1.1 $");
script_name(english: "Fedora 10 2009-2869: drupal-cck");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-2869 (drupal-cck)");
 script_set_attribute(attribute: "description", value: "The Content Construction Kit allows you create and customize fields using
a web browser. The 4.7x version of CCK creates custom content types and
allows you to add custom fields to them. In Drupal 5.x custom content
types can be created in core, and CCK allows you to add custom fields to
any content type.

-
Update Information:

Fixes DRUPAL-SA-CONTRIB-2009-013 - XSS issue:    [9]http://drupal.org/node/4065
20
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the drupal-cck package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"drupal-cck-6.x.2.2-1.fc10", release:"FC10") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
