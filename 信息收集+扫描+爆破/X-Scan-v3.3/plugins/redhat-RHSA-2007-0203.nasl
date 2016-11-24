
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25135);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0203: unzip");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0203");
 script_set_attribute(attribute: "description", value: '
  Updated unzip packages that fix two security issues and various bugs are
  now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  The unzip utility is used to list, test, or extract files from a zip
  archive.

  A race condition was found in Unzip. Local users could use this flaw to
  modify permissions of arbitrary files via a hard link attack on a file
  while it was being decompressed (CVE-2005-2475)

  A buffer overflow was found in Unzip command line argument handling.
  If a user could be tricked into running Unzip with a specially crafted long
  file name, an attacker could execute arbitrary code with that user\'s
  privileges. (CVE-2005-4667)

  As well, this update adds support for files larger than 2GB.

  All users of unzip should upgrade to these updated packages, which
  contain backported patches that resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0203.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-2475", "CVE-2005-4667");
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

if ( rpm_check( reference:"unzip-5.51-9.EL4.5", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
