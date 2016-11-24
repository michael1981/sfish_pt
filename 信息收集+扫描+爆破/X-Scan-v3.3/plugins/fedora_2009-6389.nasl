
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-6389
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(39404);
 script_version ("$Revision: 1.1 $");
script_name(english: "Fedora 10 2009-6389: drupal-views");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-6389 (drupal-views)");
 script_set_attribute(attribute: "description", value: "The views module provides a flexible method for Drupal site designers
to control how lists of content (nodes) are presented. Traditionally,
Drupal has hard-coded most of this, particularly in how taxonomy and
tracker lists are formatted.

This tool is essentially a smart query builder that, given enough
information, can build the proper query, execute it, and display the
results. It has four modes, plus a special mode, and provides an
impressive amount of functionality from these modes.

-
Update Information:


Update information :

* Advisory ID: DRUPAL-SA-CONTRIB-2009-037 [0]   * Project: Views   * Versions:
6.x-2.x   * Date: 2009-June-10   * Security risk: Moderately critical   *
Exploitable from: Remote   * Vulnerability: Cross Site Scripting (XSS), Access
Bypass    -------- DESCRIPTION
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the drupal-views package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"drupal-views-6.x.2.6-1.fc10", release:"FC10") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
