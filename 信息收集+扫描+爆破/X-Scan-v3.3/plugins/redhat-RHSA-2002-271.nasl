
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12338);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2002-271: pine");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2002-271");
 script_set_attribute(attribute: "description", value: '
  A vulnerability in Pine version 4.44 and earlier releases can cause
  Pine to crash when sent a carefully crafted email.

  [Updated 06 Feb 2003]
  Added fixed packages for Advanced Workstation 2.1

  Pine, developed at the University of Washington, is a tool for reading,
  sending, and managing electronic messages (including mail and news).

  A security problem was found in versions of Pine 4.44 and earlier. In these
  verions, Pine does not allocate enough memory for the parsing and escaping
  of the "From" header, allowing a carefully crafted email to cause a
  buffer overflow on the heap. This will result in Pine crashing.

  All users of Pine on Red Hat Linux Advanced Server are advised to
  update to these errata packages containing a patch to version 4.44
  of Pine that fixes this vulnerability.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2002-271.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2002-1320");
script_summary(english: "Check for the version of the pine packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"pine-4.44-7.21AS.0", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
