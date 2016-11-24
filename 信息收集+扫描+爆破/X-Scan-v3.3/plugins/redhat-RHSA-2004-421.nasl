
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(14214);
 script_version ("$Revision: 1.14 $");
 script_name(english: "RHSA-2004-421: galeon");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-421");
 script_set_attribute(attribute: "description", value: '
  Updated mozilla packages based on version 1.4.3 that fix a number of
  security issues for Red Hat Enterprise Linux are now available.

  Mozilla is an open source Web browser, advanced email and newsgroup
  client, IRC chat client, and HTML editor.

  A number of flaws have been found in Mozilla 1.4 that have been fixed in
  the Mozilla 1.4.3 release:

  Zen Parse reported improper input validation to the SOAPParameter object
  constructor leading to an integer overflow and controllable heap
  corruption. Malicious JavaScript could be written to utilize this flaw and
  could allow arbitrary code execution. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2004-0722 to
  this issue.

  During a source code audit, Chris Evans discovered a buffer overflow and
  integer overflows which affect the libpng code inside Mozilla. An attacker
  could create a carefully crafted PNG file in such a way that it would cause
  Mozilla to crash or execute arbitrary code when the image was viewed.
  (CAN-2004-0597, CAN-2004-0599)

  Zen Parse reported a flaw in the POP3 capability. A malicious POP3 server
  could send a carefully crafted response that would cause a heap overflow
  and potentially allow execution of arbitrary code as the user running
  Mozilla. (CAN-2004-0757)

  Marcel Boesch found a flaw that allows a CA certificate to be imported with
  a DN the same as that of the built-in CA root certificates, which can cause
  a denial of service to SSL pages, as the malicious certificate is treated
  as invalid. (CAN-2004-0758)

  Met - Martin Hassman reported a flaw in Mozilla that could allow malicious
  Javascript code to upload local files from a users machine without
  requiring confirmation. (CAN-2004-0759)

  Mindlock Security reported a flaw in ftp URI handling. By using a NULL
  character (%00) in a ftp URI, Mozilla can be confused into opening a
  resource as a different MIME type. (CAN-2004-0760)

  Mozilla does not properly prevent a frame in one domain from injecting
  content into a frame that belongs to another domain, which facilitates
  website spoofing and other attacks, also known as the frame injection
  vulnerability. (CAN-2004-0718)

  Tolga Tarhan reported a flaw that can allow a malicious webpage to use a
  redirect sequence to spoof the security lock icon that makes a webpage
  appear to be encrypted. (CAN-2004-0761)

  Jesse Ruderman reported a security issue that affects a number of browsers
  including Mozilla that could allow malicious websites to install arbitrary
  extensions by using interactive events to manipulate the XPInstall Security
  dialog box. (CAN-2004-0762)

  Emmanouel Kellinis discovered a caching flaw in Mozilla which allows
  malicious websites to spoof certificates of trusted websites via
  redirects and Javascript that uses the "onunload" method. (CAN-2004-0763)

  Mozilla allowed malicious websites to hijack the user interface via the
  "chrome" flag and XML User Interface Language (XUL) files. (CAN-2004-0764)

  The cert_TestHostName function in Mozilla only checks the hostname portion
  of a certificate when the hostname portion of the URI is not a fully
  qualified domain name (FQDN). This flaw could be used for spoofing if an
  attacker had control of machines on a default DNS search path. (CAN-2004-0765)

  All users are advised to update to these erratum packages which contain a
  snapshot of Mozilla 1.4.3 including backported fixes and are not vulnerable
  to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-421.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0597", "CVE-2004-0599", "CVE-2004-0718", "CVE-2004-0722", "CVE-2004-0757", "CVE-2004-0758", "CVE-2004-0759", "CVE-2004-0760", "CVE-2004-0761", "CVE-2004-0762", "CVE-2004-0763", "CVE-2004-0764", "CVE-2004-0765");
script_summary(english: "Check for the version of the galeon packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"galeon-1.2.13-3.2.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.4.3-2.1.2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.4.3-2.1.2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.4.3-2.1.2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.4.3-2.1.2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.4.3-2.1.2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.4.3-2.1.2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.4.3-2.1.2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.4.3-2.1.2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.4.3-2.1.2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.4.3-2.1.2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.4.3-3.0.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.4.3-3.0.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.4.3-3.0.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.4.3-3.0.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.4.3-3.0.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.4.3-3.0.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.4.3-3.0.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.4.3-3.0.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.4.3-3.0.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.4.3-3.0.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
