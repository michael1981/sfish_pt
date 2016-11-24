
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12436);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2003-372: wget");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-372");
 script_set_attribute(attribute: "description", value: '
  Updated wget packages that correct a buffer overrun are now available.

  GNU Wget is a file-retrieval utility that uses the HTTP and FTP protocols.

  A buffer overflow in the url_filename function for wget 1.8.1 allows
  attackers to cause a segmentation fault via a long URL. Red Hat does not
  believe that this issue is exploitable to allow an attacker to be able to
  run arbitrary code. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2002-1565 to this issue.

  Users of wget should install the erratum package, which contains a
  backported security patch and is not vulnerable to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-372.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2002-1565");
script_summary(english: "Check for the version of the wget packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"wget-1.8.2-14.72", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
