
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12463);
 script_version ("$Revision: 1.8 $");
 script_name(english: "RHSA-2004-056: util");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-056");
 script_set_attribute(attribute: "description", value: '
  Updated util-linux packages that fix an information leak in the login
  program are now available.

  The util-linux package contains a large variety of low-level system
  utilities that are necessary for a Linux system to function.

  In some situations, the login program could use a pointer that had been
  freed and reallocated. This could cause unintentional data leakage.

  Note: Red Hat Enterprise Linux 3 is not vulnerable to this issue.

  It is recommended that all users upgrade to these updated packages, which
  are not vulnerable to this issue.

  Red Hat would like to thank Matthew Lee of Fleming College for finding and
  reporting this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-056.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0080");
script_summary(english: "Check for the version of the util packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"util-linux-2.11f-20.4", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
