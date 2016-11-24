
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(26953);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2007-0932: pwlib");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0932");
 script_set_attribute(attribute: "description", value: '
  Updated pwlib packages that fix a security issue are now available for Red
  Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  PWLib is a library used to support cross-platform applications.

  In Red Hat Enterprise Linux 5, the Ekiga teleconferencing application uses
  PWLib.

  A memory management flaw was discovered in PWLib. An attacker could use this
  flaw to crash an application, such as Ekiga, which is linked with pwlib
  (CVE-2007-4897).

  Users should upgrade to these updated packages which contain a backported
  patch to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0932.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-4897");
script_summary(english: "Check for the version of the pwlib packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"pwlib-1.10.1-7.0.1.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
