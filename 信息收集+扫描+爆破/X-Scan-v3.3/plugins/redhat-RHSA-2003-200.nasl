
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12403);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2003-200: unzip");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-200");
 script_set_attribute(attribute: "description", value: '
  Updated unzip packages resolving a vulnerability allowing arbitrary files
  to be overwritten are now available.

  [Updated 15 August 2003]
  Ben Laurie found that the original patch to fix this issue missed a case
  where the path component included a quoted slash. These updated packages
  contain a new patch that corrects this issue.

  The unzip utility is used for manipulating archives, which are multiple
  files stored inside of a single file.

  A vulnerabilitiy in unzip version 5.50 and earlier allows attackers to
  overwrite arbitrary files during archive extraction by placing invalid
  (non-printable) characters between two "." characters. These non-printable
  characters are filtered, resulting in a ".." sequence. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2003-0282 to this issue.

  This erratum includes a patch ensuring that non-printable characters do not
  make it possible for a malicious .zip file to write to parent directories
  unless the "-:" command line parameter is specified.

  Users of unzip are advised to upgrade to these updated packages, which are
  not vulnerable to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-200.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0282");
script_summary(english: "Check for the version of the unzip packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"unzip-5.50-30", release:'RHEL2.1') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
