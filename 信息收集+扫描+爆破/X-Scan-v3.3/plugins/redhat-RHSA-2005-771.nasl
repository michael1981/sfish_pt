
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(19833);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-771: wget");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-771");
 script_set_attribute(attribute: "description", value: '
  Updated wget package that fixes several security issues is now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  GNU Wget is a file retrieval utility that can use either the HTTP or
  FTP protocols.

  A bug was found in the way wget writes files to the local disk. If a
  malicious local user has write access to the directory wget is saving a
  file into, it is possible to overwrite files that the user running wget
  has write access to. (CAN-2004-2014)

  A bug was found in the way wget filters redirection URLs. It is possible
  for a malicious Web server to overwrite files the user running wget has
  write access to. Note: in order for this attack to succeed the local
  DNS would need to resolve ".." to an IP address, which is an unlikely
  situation. (CAN-2004-1487)

  A bug was found in the way wget displays HTTP response codes. It is
  possible that a malicious web server could inject a specially crafted
  terminal escape sequence capable of misleading the user running wget.
  (CAN-2004-1488)

  Users should upgrade to this updated package, which contains a version of
  wget that is not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-771.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-1487", "CVE-2004-1488", "CVE-2004-2014");
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

if ( rpm_check( reference:"wget-1.10.1-0.AS21", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wget-1.10.1-1.30E.1", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wget-1.10.1-2.4E.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
