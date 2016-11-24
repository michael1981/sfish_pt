
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34034);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0855: openssh");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0855");
 script_set_attribute(attribute: "description", value: '
  Updated openssh packages are now available for Red Hat Enterprise Linux 4,
  Red Hat Enterprise Linux 5, and Red Hat Enterprise Linux 4.5 Extended
  Update Support.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  OpenSSH is OpenBSD\'s SSH (Secure SHell) protocol implementation.

  Last week Red Hat detected an intrusion on certain of its computer systems
  and took immediate action. While the investigation into the intrusion is
  on-going, our initial focus was to review and test the distribution
  channel we use with our customers, Red Hat Network (RHN) and its associated
  security measures. Based on these efforts, we remain highly confident that
  our systems and processes prevented the intrusion from compromising RHN or
  the content distributed via RHN and accordingly believe that customers who
  keep their systems updated using Red Hat Network are not at risk. We are
  issuing this alert primarily for those who may obtain Red Hat binary
  packages via channels other than those of official Red Hat subscribers.

  In connection with the incident, the intruder was able to sign a small
  number of OpenSSH packages relating only to Red Hat Enterprise Linux 4
  (i386 and x86_64 architectures only) and Red Hat Enterprise Linux 5 (x86_64
  architecture only). As a precautionary measure, we are releasing an
  updated version of these packages, and have published a list of the
  tampered packages and how to detect them at
  http://www.redhat.com/security/data/openssh-blacklist.html

  To reiterate, our processes and efforts to date indicate that packages
  obtained by Red Hat Enterprise Linux subscribers via Red Hat Network are
  not at risk.

  These packages also fix a low severity flaw in the way ssh handles X11
  cookies when creating X11 forwarding connections. When ssh was unable to
  create untrusted cookie, ssh used a trusted cookie instead, possibly
  allowing the administrative user of a untrusted remote server, or untrusted
  application run on the remote server, to gain unintended access to a users
  local X server. (CVE-2007-4752)


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0855.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-4752", "CVE-2008-3844");
script_summary(english: "Check for the version of the openssh packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"openssh-4.3p2-26.el5_2.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-4.3p2-26.el5_2.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-clients-4.3p2-26.el5_2.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-server-4.3p2-26.el5_2.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-3.9p1-11.el4_7", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-3.9p1-11.el4_7", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-gnome-3.9p1-11.el4_7", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-clients-3.9p1-11.el4_7", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-server-3.9p1-11.el4_7", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-3.9p1-10.RHEL4.20", release:'RHEL4.5.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-3.9p1-10.RHEL4.20", release:'RHEL4.5.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-gnome-3.9p1-10.RHEL4.20", release:'RHEL4.5.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-clients-3.9p1-10.RHEL4.20", release:'RHEL4.5.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-server-3.9p1-10.RHEL4.20", release:'RHEL4.5.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
