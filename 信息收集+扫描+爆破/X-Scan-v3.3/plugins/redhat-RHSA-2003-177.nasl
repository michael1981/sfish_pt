
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12397);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2003-177: rhn_register");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-177");
 script_set_attribute(attribute: "description", value: '
  Updated versions of the rhn_register and up2date packages are now
  available. The new packages include many bug fixes, and a few new features.

  The rhn_register and up2date packages contain the software necessary to
  take advantage of Red Hat Network functionality.

  The up2date package incorporates improvements in handling package
  dependencies and "obsoletes" processing, along with many other bug fixes.

  This release also includes an updated RHNS-CA-CERT file, which contains an
  additional CA certificate. This is needed so that up2date can continue to
  communicate with Red Hat Network once the current CA certificate reaches
  its August 2003 expiration date.

  All users of Red Hat Network should therefore upgrade to these erratum
  packages.


');
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-177.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_summary(english: "Check for the version of the rhn_register packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"rhn_register-2.8.34-1.2.1AS", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rhn_register-gnome-2.8.34-1.2.1AS", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"up2date-2.8.45-1.2.1AS", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"up2date-gnome-2.8.45-1.2.1AS", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
