
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(20205);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2005-825: lm_sensors");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-825");
 script_set_attribute(attribute: "description", value: '
  Updated lm_sensors packages that fix an insecure file issue are now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  The lm_sensors package includes a collection of modules for general SMBus
  access and hardware monitoring. This package requires special support which
  is not in standard version 2.2 kernels.

  A bug was found in the way the pwmconfig tool creates temporary files. It
  is possible that a local attacker could leverage this flaw to overwrite
  arbitrary files located on the system. The Common Vulnerabilities and
  Exposures project has assigned the name CVE-2005-2672 to this issue.

  Users of lm_sensors are advised to upgrade to these updated packages, which
  contain a backported patch that resolves this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-825.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-2672");
script_summary(english: "Check for the version of the lm_sensors packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"lm_sensors-2.8.7-2.40.3", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lm_sensors-devel-2.8.7-2.40.3", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
