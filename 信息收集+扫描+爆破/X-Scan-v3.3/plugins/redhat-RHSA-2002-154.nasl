
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12314);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2002-154: mm");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2002-154");
 script_set_attribute(attribute: "description", value: '
  Updated mm packages are now available for Red Hat Linux Advanced Server.
  This update addresses possible vulnerabilities in how the MM library
  opens temporary files.

  The MM library provides an abstraction layer which allows related processes
  to easily share data. On systems where shared memory or other
  inter-process communication mechanisms are not available, the MM library
  will emulate them using temporary files. MM is used in Red Hat Linux to
  providing shared memory pools to Apache modules.

  Versions of MM up to and including 1.1.3 open temporary files in an unsafe
  manner, allowing a malicious local user to cause an application which uses
  MM to overwrite any file to which it has write access.

  All users are advised to upgrade to these errata packages which contain a
  patched version of MM that is not vulnerable to this issue.

  Thanks to Marcus Meissner for providing a patch for this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2002-154.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2002-0658");
script_summary(english: "Check for the version of the mm packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"mm-1.1.3-8", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mm-devel-1.1.3-8", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
