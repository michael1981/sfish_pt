
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12346);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2002-312: openldap");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2002-312");
 script_set_attribute(attribute: "description", value: '
  Updated OpenLDAP packages are available which fix a number of local and
  remote buffer overflows in libldap as well as the slapd and slurpd daemons.
  Additionally, potential issues stemming from using user-specified LDAP
  configuration files have been addressed.

  [Updated 06 Feb 2003]
  Added fixed packages for Red Hat Linux Advanced Workstation 2.1

  [Updated 13 Aug 2003]
  Added openldap12 packages for Red Hat Linux Advanced Server 2.1
  and Advanced Workstation 2.1 that were originally left out of this errata.

  OpenLDAP is a suite of LDAP (Lightweight Directory Access Protocol)
  applications and development tools. LDAP is a set of protocols for
  accessing directory services. In an audit of OpenLDAP by SuSE, a number of
  potential security issues were found.

  The following is a list of these issues:

  When reading configuration files, libldap reads the current user\'s .ldaprc
  file even in applications being run with elevated privileges.

  Slurpd would overflow an internal buffer if the command-line argument used
  with the -t or -r flags is too long, or if the name of a file for which it
  attempted to create an advisory lock is too long.

  When parsing filters, the getfilter family of functions from libldap can
  overflow an internal buffer by supplying a carefully crafted
  ldapfilter.conf file.

  When processing LDAP entry display templates, libldap can overflow an
  internal buffer by supplying a carefully crafted ldaptemplates.conf file.

  When parsing an access control list, slapd can overflow an internal buffer.

  When constructing the name of the file used for logging rejected
  replication requests, slapd overflows an internal buffer if the size
  of the generated name is too large. It can also destroy the contents of any
  file owned by the user \'ldap\' due to a race condition in the subsequent
  creation of the log file.

  All of these potential security issues are corrected by the packages
  contained within this erratum.

  Red Hat Linux Advanced Server users who use LDAP are advised to
  install the updated OpenLDAP packages contained within this erratum.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2002-312.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2002-1378", "CVE-2002-1379", "CVE-2002-1508");
script_summary(english: "Check for the version of the openldap packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"openldap-2.0.27-2.7.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openldap-clients-2.0.27-2.7.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openldap-devel-2.0.27-2.7.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openldap-servers-2.0.27-2.7.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openldap12-1.2.13-8", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
