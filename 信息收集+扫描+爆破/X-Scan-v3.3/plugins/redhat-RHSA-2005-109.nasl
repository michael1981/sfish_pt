
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(16385);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-109: python");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-109");
 script_set_attribute(attribute: "description", value: '
  Updated Python packages that fix a security issue are now available for Red
  Hat Enterprise Linux 3.

  Python is an interpreted, interactive, object-oriented programming
  language.

  An object traversal bug was found in the Python SimpleXMLRPCServer. This
  bug could allow a remote untrusted user to do unrestricted object traversal
  and allow them to access or change function internals using the im_* and
  func_* attributes. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2005-0089 to this issue.

  Users of Python are advised to upgrade to these updated packages, which
  contain backported patches to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-109.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-0089");
script_summary(english: "Check for the version of the python packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"python-2.2.3-6.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"python-devel-2.2.3-6.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"python-tools-2.2.3-6.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tkinter-2.2.3-6.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
