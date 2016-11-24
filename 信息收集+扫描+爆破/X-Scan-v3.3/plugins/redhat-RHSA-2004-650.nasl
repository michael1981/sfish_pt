
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(15991);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2004-650: libxml");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-650");
 script_set_attribute(attribute: "description", value: '
  An updated libxml package that fixes multiple buffer overflows is now
  available.

  [Updated 24 May 2005]
  Multilib packages have been added to this advisory

  The libxml package contains a library for manipulating XML files.

  Multiple buffer overflow bugs have been found in libxml versions prior to
  2.6.14. If an attacker can trick a user into passing a specially crafted
  FTP URL or FTP proxy URL to an application that uses the vulnerable
  functions of libxml, it could be possible to execute arbitrary code.
  Additionally, if an attacker can return a specially crafted DNS request to
  libxml, it could be possible to execute arbitrary code. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2004-0989 to this issue.

  Yuuichi Teranishi discovered a flaw in libxml versions prior to 2.6.6.
  When fetching a remote resource via FTP or HTTP, libxml uses special
  parsing routines. These routines can overflow a buffer if passed a very
  long URL. If an attacker is able to find an application using libxml that
  parses remote resources and allows them to influence the URL, then this
  flaw could be used to execute arbitrary code. The Common Vulnerabilities
  and Exposures project (cve.mitre.org) has assigned the name CAN-2004-0110
  to this issue.

  All users are advised to upgrade to this updated package, which contains
  backported patches and is not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-650.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0110", "CVE-2004-0989");
script_summary(english: "Check for the version of the libxml packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libxml-1.8.14-3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxml-devel-1.8.14-3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxml-1.8.17-9.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxml-devel-1.8.17-9.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
