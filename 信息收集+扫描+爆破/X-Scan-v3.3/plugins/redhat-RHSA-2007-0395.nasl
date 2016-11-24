
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25519);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0395: mod_perl");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0395");
 script_set_attribute(attribute: "description", value: '
  Updated mod_perl packages that fix a security issue are now available for Red
  Hat Enterprise Linux 3, 4, 5.

  This update has been rated as having low security impact by the Red
  Hat Security Response Team.

  Mod_perl incorporates a Perl interpreter into the Apache web server,
  so that the Apache web server can directly execute Perl code.

  An issue was found in the "namespace_from_uri" method of the
  ModPerl::RegistryCooker class. If a server implemented a mod_perl registry
  module using this method, a remote attacker requesting a carefully crafted
  URI can cause resource consumption, which could lead to a denial of service
  (CVE-2007-1349).

  Users of mod_perl should update to these erratum packages which contain a
  backported fix to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0395.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-1349");
script_summary(english: "Check for the version of the mod_perl packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"mod_perl-2.0.2-6.3.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mod_perl-devel-2.0.2-6.3.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mod_perl-1.99_09-12.ent", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mod_perl-devel-1.99_09-12.ent", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mod_perl-1.99_16-4.5", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mod_perl-devel-1.99_16-4.5", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
