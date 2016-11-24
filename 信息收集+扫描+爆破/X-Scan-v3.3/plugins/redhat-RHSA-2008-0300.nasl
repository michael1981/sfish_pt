
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(32424);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2008-0300: bind");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0300");
 script_set_attribute(attribute: "description", value: '
  Updated bind packages that fix two security issues, several bugs, and add
  enhancements are now available for Red Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The Berkeley Internet Name Domain (BIND) is an implementation of the Domain
  Name System (DNS) protocols. BIND includes a DNS server (named); a resolver
  library (routines for applications to use when interfacing with DNS); and
  tools for verifying that the DNS server is operating correctly.

  It was discovered that the bind packages created the "rndc.key" file with
  insecure file permissions. This allowed any local user to read the content
  of this file. A local user could use this flaw to control some aspects of
  the named daemon by using the rndc utility, for example, stopping the named
  daemon. This problem did not affect systems with the bind-chroot package
  installed. (CVE-2007-6283)

  A buffer overflow flaw was discovered in the "inet_network()" function, as
  implemented by libbind. An attacker could use this flaw to crash an
  application calling this function, with an argument provided from an
  untrusted source. (CVE-2008-0122)

  As well, these updated packages fix the following bugs:

  * when using an LDAP backend, missing function declarations caused
  segmentation faults, due to stripped pointers on machines where pointers
  are longer than integers.

  * starting named may have resulted in named crashing, due to a race
  condition during D-BUS connection initialization. This has been resolved in
  these updated packages.

  * the named init script returned incorrect error codes, causing the
  "status" command to return an incorrect status. In these updated packages,
  the named init script is Linux Standard Base (LSB) compliant.

  * in these updated packages, the "rndc [command] [zone]" command, where
  [command] is an rndc command, and [zone] is the specified zone, will find
  the [zone] if the zone is unique to all views.

  * the default named log rotation script did not work correctly when using
  the bind-chroot package. In these updated packages, installing
  bind-chroot creates the symbolic link "/var/log/named.log", which points
  to "/var/named/chroot/var/log/named.log", which resolves this issue.

  * a previous bind update incorrectly changed the permissions on the
  "/etc/openldap/schema/dnszone.schema" file to mode 640, instead of mode
  644, which resulted in OpenLDAP not being able to start. In these updated
  packages, the permissions are correctly set to mode 644.

  * the "checkconfig" parameter was missing in the named usage report. For
  example, running the "service named" command did not return "checkconfig"
  in the list of available options.

  * due to a bug in the named init script not handling the rndc return value
  correctly, the "service named stop" and "service named restart" commands
  failed on certain systems.

  * the bind-chroot spec file printed errors when running the "%pre" and
  "%post" sections. Errors such as the following occurred:

  Locating //etc/named.conf failed:
  [FAILED]

  This has been resolved in these updated packages.

  * installing the bind-chroot package creates a "/dev/random" file in the
  chroot environment; however, the "/dev/random" file had an incorrect
  SELinux label. Starting named resulted in an \'avc: denied { getattr } for
  pid=[pid] comm="named" path="/dev/random"\' error being logged. The
  "/dev/random" file has the correct SELinux label in these updated packages.

  * in certain situations, running the "bind +trace" command resulted in
  random segmentation faults.

  As well, these updated packages add the following enhancements:

  * support has been added for GSS-TSIG (RFC 3645).

  * the "named.root" file has been updated to reflect the new address for
  L.ROOT-SERVERS.NET.

  * updates BIND to the latest 9.3 maintenance release.

  All users of bind are advised to upgrade to these updated packages, which
  resolve these issues and add these enhancements.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0300.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-6283", "CVE-2008-0122");
script_summary(english: "Check for the version of the bind packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"bind-9.3.4-6.P1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bind-chroot-9.3.4-6.P1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bind-devel-9.3.4-6.P1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bind-libbind-devel-9.3.4-6.P1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bind-libs-9.3.4-6.P1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bind-sdb-9.3.4-6.P1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bind-utils-9.3.4-6.P1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"caching-nameserver-9.3.4-6.P1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
