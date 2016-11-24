
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12321);
 script_version ("$Revision: 1.8 $");
 script_name(english: "RHSA-2002-180: nss_ldap");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2002-180");
 script_set_attribute(attribute: "description", value: '
  Updated nss_ldap packages are now available for Red Hat Linux Advanced
  Server 2.1. These updates fix a potential buffer overflow which can occur
  when nss_ldap is set to configure itself using information stored in DNS
  as well as a format string bug in logging functions used in pam_ldap.

  [Updated 09 Jan 2003]
  Added fixed packages for the Itanium (IA64) architecture.

  [Updated 06 Feb 2003]
  Added fixed packages for Advanced Workstation 2.1

  nss_ldap is a set of C library extensions that allow X.500 and LDAP
  directory servers to be used as a primary source of aliases, ethers,
  groups, hosts, networks, protocols, users, RPCs, services, and shadow
  passwords (instead of or in addition to using flat files or NIS).

  When versions of nss_ldap prior to nss_ldap-198 are configured without a
  value for the "host" setting, nss_ldap will attempt to configure itself by
  using SRV records stored in DNS. When parsing the results of the DNS
  query, nss_ldap does not check that data returned by the server will fit
  into an internal buffer, leaving it vulnerable to a buffer overflow
  The Common Vulnerabilities and Exposures project has assigned the name
  CAN-2002-0825 to this issue.

  When versions of nss_ldap prior to nss_ldap-199 are configured without a
  value for the "host" setting, nss_ldap will attempt to configure itself by
  using SRV records stored in DNS. When parsing the results of the DNS
  query, nss_ldap does not check that the data returned has not been
  truncated by the resolver libraries to avoid a buffer overflow, and may
  attempt to parse more data than is actually available, leaving it
  vulnerable to a read buffer overflow.

  Versions of pam_ldap prior to version 144 include a format string bug in
  the logging function. The packages included in this erratum update pam_ldap
  to version 144, fixing this bug. The Common Vulnerabilities and Exposures
  project has assigned the name CAN-2002-0374 to this issue.

  All users of nss_ldap should update to these errata packages which are not
  vulnerable to the above issues. These packages are based on nss_ldap-189
  with the addition of a backported security patch and pam_ldap version 144.

  Thanks to the nss_ldap and pam_ldap team at padl.com for providing
  information about these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2002-180.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2002-0374", "CVE-2002-0825");
script_summary(english: "Check for the version of the nss_ldap packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"nss_ldap-189-4", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
