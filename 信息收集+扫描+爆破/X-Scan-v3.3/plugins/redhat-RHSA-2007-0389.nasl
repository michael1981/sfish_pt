
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25363);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0389: quagga");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0389");
 script_set_attribute(attribute: "description", value: '
  An updated quagga package that fixes a security bug is now available for
  Red Hat Enterprise Linux 3, 4 and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Quagga is a TCP/IP based routing software suite.

  An out of bounds memory read flaw was discovered in Quagga\'s bgpd. A
  configured peer of bgpd could cause Quagga to crash, leading to a denial of
  service (CVE-2007-1995).

  All users of Quagga should upgrade to this updated package, which
  contains a backported patch to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0389.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-1995");
script_summary(english: "Check for the version of the quagga packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"quagga-0.98.6-2.1.0.1.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"quagga-contrib-0.98.6-2.1.0.1.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"quagga-devel-0.98.6-2.1.0.1.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"quagga-0.96.2-12.3E", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"quagga-0.98.3-2.4.0.1.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"quagga-contrib-0.98.3-2.4.0.1.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"quagga-devel-0.98.3-2.4.0.1.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
