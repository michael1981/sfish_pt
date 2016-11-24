
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12418);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2003-268: up");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-268");
 script_set_attribute(attribute: "description", value: '
  New versions of the up2date and rhn_register clients are available and
  are required for continued access to Red Hat Network.

  The rhn_register and up2date packages contain the software necessary to
  take advantage of Red Hat Network functionality.

  This erratum includes an updated RHNS-CA-CERT file, which contains a new CA
  certificate. This new certificate is needed so that up2date can continue
  to communicate with Red Hat Network after 28 August 2003. Without this
  updated certificate, users will see SSL Connection Errors reported by
  up2date or rhn_register.

  All users must upgrade to these erratum packages in order to continue to
  use Red Hat Network. This includes both interactive use of up2date, as
  well as actions scheduled by the RHN website.


');
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-268.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_summary(english: "Check for the version of the up packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"up2date-2.8.46.3-1.2.1AS", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"up2date-gnome-2.8.46.3-1.2.1AS", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
