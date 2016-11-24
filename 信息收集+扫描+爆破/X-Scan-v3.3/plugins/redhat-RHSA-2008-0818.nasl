
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33884);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0818: hpijs");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0818");
 script_set_attribute(attribute: "description", value: '
  Updated hplip packages that fix various security issues are now available
  for Red Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The hplip (Hewlett-Packard Linux Imaging and Printing) packages provide
  drivers for Hewlett-Packard printers and multifunction peripherals.

  A flaw was discovered in the hplip alert-mailing functionality. A local
  attacker could elevate their privileges by using specially-crafted packets
  to trigger alert mails, which are sent by the root account. (CVE-2008-2940)

  A flaw was discovered in the hpssd message parser. By sending
  specially-crafted packets, a local attacker could cause a denial of
  service, stopping the hpssd process. (CVE-2008-2941)

  Users of hplip should upgrade to these updated packages, which contain
  backported patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0818.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-2940", "CVE-2008-2941");
script_summary(english: "Check for the version of the hpijs packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"hpijs-1.6.7-4.1.el5_2.4", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hplip-1.6.7-4.1.el5_2.4", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libsane-hpaio-1.6.7-4.1.el5_2.4", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
