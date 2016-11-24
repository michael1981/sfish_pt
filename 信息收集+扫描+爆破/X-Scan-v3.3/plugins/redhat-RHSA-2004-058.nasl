
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12464);
 script_version ("$Revision: 1.8 $");
 script_name(english: "RHSA-2004-058: mod_python");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-058");
 script_set_attribute(attribute: "description", value: '
  Updated mod_python packages that fix a denial of service vulnerability are
  now available for Red Hat Enterprise Linux.

  mod_python embeds the Python language interpreter within the Apache httpd
  server.

  A bug has been found in mod_python versions 2.7.10 and earlier that can
  lead to a denial of service vulnerability. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2003-0973 to
  this issue.

  Although Red Hat Enterprise Linux shipped with a version of mod_python that
  contains this bug, our testing was unable to trigger the denial of service
  vulnerability. However, mod_python users are advised to upgrade to these
  errata packages, which contain a backported patch that corrects this bug.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-058.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0973", "CVE-2004-0096");
script_summary(english: "Check for the version of the mod_python packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"mod_python-2.7.8-2", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mod_python-3.0.3-3.ent", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
