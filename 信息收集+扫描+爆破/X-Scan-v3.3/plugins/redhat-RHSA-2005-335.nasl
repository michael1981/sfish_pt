
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(17626);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-335: devhelp");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-335");
 script_set_attribute(attribute: "description", value: '
  Updated mozilla packages that fix various bugs are now available.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Mozilla is an open source Web browser, advanced email and newsgroup client,
  IRC chat client, and HTML editor.

  A buffer overflow bug was found in the way Mozilla processes GIF images. It
  is possible for an attacker to create a specially crafted GIF image, which
  when viewed by a victim will execute arbitrary code as the victim. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CAN-2005-0399 to this issue.

  A bug was found in the way Mozilla responds to proxy auth requests. It is
  possible for a malicious webserver to steal credentials from a victims
  browser by issuing a 407 proxy authentication request. (CAN-2005-0147)

  A bug was found in the way Mozilla displays dialog windows. It is possible
  that a malicious web page which is being displayed in a background tab
  could present the user with a dialog window appearing to come from the
  active page. (CAN-2004-1380)

  A bug was found in the way Mozilla Mail handles cookies when loading
  content over HTTP regardless of the user\'s preference. It is possible that
  a particular user could be tracked through the use of malicious mail
  messages which load content over HTTP. (CAN-2005-0149)

  A flaw was found in the way Mozilla displays international domain names. It
  is possible for an attacker to display a valid URL, tricking the user into
  thinking they are viewing a legitimate webpage when they are not.
  (CAN-2005-0233)

  A bug was found in the way Mozilla handles pop-up windows. It is possible
  for a malicious website to control the content in an unrelated site\'s
  pop-up window. (CAN-2004-1156)

  A bug was found in the way Mozilla saves temporary files. Temporary files
  are saved with world readable permissions, which could allow a local
  malicious user to view potentially sensitive data. (CAN-2005-0142)

  A bug was found in the way Mozilla handles synthetic middle click events.
  It is possible for a malicious web page to steal the contents of a victims
  clipboard. (CAN-2005-0146)

  A bug was found in the way Mozilla processes XUL content. If a malicious
  web page can trick a user into dragging an object, it is possible to load
  malicious XUL content. (CAN-2005-0401)

  A bug was found in the way Mozilla loads links in a new tab which are
  middle clicked. A malicious web page could read local files or modify
  privileged chrom settings. (CAN-2005-0141)

  A bug was found in the way Mozilla displays the secure site icon. A
  malicious web page can use a view-source URL targetted at a secure page,
  while loading an insecure page, yet the secure site icon shows the previous
  secure state. (CAN-2005-0144)

  A bug was found in the way Mozilla displays the secure site icon. A
  malicious web page can display the secure site icon by loading a binary
  file from a secured site. (CAN-2005-0143)

  A bug was found in the way Mozilla displays the download dialog window. A
  malicious site can obfuscate the content displayed in the source field,
  tricking a user into thinking they are downloading content from a trusted
  source. (CAN-2005-0585)

  Users of Mozilla are advised to upgrade to this updated package which
  contains Mozilla version 1.7.6 to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-335.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-1380", "CVE-2005-0141", "CVE-2005-0142", "CVE-2005-0143", "CVE-2005-0144", "CVE-2005-0146", "CVE-2005-0149", "CVE-2005-0399", "CVE-2005-0401");
script_summary(english: "Check for the version of the devhelp packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"devhelp-0.9.2-2.4.3", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"devhelp-devel-0.9.2-2.4.3", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"evolution-2.0.2-14", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"evolution-devel-2.0.2-14", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.7.6-1.4.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.7.6-1.4.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.6-1.4.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.6-1.4.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.7.6-1.4.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.6-1.4.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.7.6-1.4.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.7.6-1.4.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.7.6-1.4.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.7.6-1.4.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
