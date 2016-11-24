
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(16264);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-068: less");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-068");
 script_set_attribute(attribute: "description", value: '
  An updated less package that fixes segmentation fault when viewing binary
  files is now available.

  The less utility is a text file browser that resembles more, but has
  extended capabilities.

  Victor Ashik discovered a heap based buffer overflow in less, caused by a
  patch added to the less package in Red Hat Enterprise Linux 3. An attacker
  could construct a carefully crafted file that could cause less to crash or
  possibly execute arbitrary code when opened. The Common Vulnerabilities
  and Exposures project (cve.mitre.org) has assigned the name CAN-2005-0086
  to this issue. Note that this issue only affects the version of less
  distributed with Red Hat Enterprise Linux 3.

  Red Hat believes that the Exec-Shield technology (enabled by default since
  Update 3) will block attempts to remotely exploit this vulnerability on x86
  architectures.

  All users of the less package should upgrade to this updated package,
  which resolves this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-068.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-0086");
script_summary(english: "Check for the version of the less packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"less-378-12", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
