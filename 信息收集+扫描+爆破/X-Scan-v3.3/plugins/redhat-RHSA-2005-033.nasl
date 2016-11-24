
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(17167);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-033: alsa");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-033");
 script_set_attribute(attribute: "description", value: '
  An updated alsa-lib package that fixes a flaw that disabled stack execution
  protection is now available for Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red Hat
  Security Response Team.

  The alsa-lib package provides a library of functions for communication with
  kernel sound drivers.

  A flaw in the alsa mixer code was discovered that caused stack
  execution protection to be disabled for the libasound.so library.
  The effect of this flaw is that stack execution protection, through NX or
  Exec-Shield, would be disabled for any application linked to libasound.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CAN-2005-0087 to this issue

  Users are advised to upgrade to this updated package, which contains a
  patched version of the library which correctly enables stack execution
  protection.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-033.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-0087");
script_summary(english: "Check for the version of the alsa packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"alsa-lib-1.0.6-5.RHEL4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"alsa-lib-devel-1.0.6-5.RHEL4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
