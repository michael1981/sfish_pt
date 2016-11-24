# This script was automatically generated from the 296-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27869);
script_version("$Revision: 1.4 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "296-2");
script_summary(english:"Firefox vulnerabilities");
script_name(english:"USN296-2 : Firefox vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- firefox 
- firefox-dev 
- firefox-dom-inspector 
- firefox-gnome-support 
- mozilla-firefox 
- mozilla-firefox-dev 
- mozilla-firefox-dom-inspector 
- mozilla-firefox-gnome-support 
');
script_set_attribute(attribute:'description', value: 'USN-296-1 fixed several vulnerabilities in Firefox for the Ubuntu 6.06
LTS release. This update provides the corresponding fixes for Ubuntu
5.04 and Ubuntu 5.10.

For reference, these are the details of the original USN:

  Jonas Sicking discovered that under some circumstances persisted XUL
  attributes are associated with the wrong URL. A malicious web site
  could exploit this to execute arbitrary code with the privileges of
  the user. (MFSA 2006-35, CVE-2006-2775)
  
  Paul Nickerson discovered that content-defined setters on an object
  prototype were getting called by privileged UI code. It was
  demonstrated that this could be exploited to run arbitrary web script
  with full user privileges (MFSA 2006-37, CVE-2006-2776). A similar
  attack was discovered by moz_bug_r_a4 that leveraged SelectionObject
  notifications that were called in privileged context. (MFSA 2006-43,
  CVE-2006-2777)
  
  Mikolaj Habryn discovered a buffer overflow in the crypto.signText()
  function. By tricking a user to visit 
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- firefox-1.0.8-0ubuntu5.10.1 (Ubuntu 5.10)
- firefox-dev-1.0.8-0ubuntu5.10.1 (Ubuntu 5.10)
- firefox-dom-inspector-1.0.8-0ubuntu5.10.1 (Ubuntu 5.10)
- firefox-gnome-support-1.0.8-0ubuntu5.10.1 (Ubuntu 5.10)
- mozilla-firefox-1.0.8-0ubuntu5.10.1 (Ubuntu 5.10)
- mozilla-firefox-dev-1.0.8-0ubuntu5.10.1 (Ubuntu 5.10)
- mozilla-firefox-dom-inspector-1.0.8-0ubuntu5.04.1 (Ubuntu 5.04)
- mozilla-firefox-gnome-support-1.0.8-0ubuntu5.04.1 (Ubuntu 5.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2005-0752","CVE-2006-1729","CVE-2006-2775","CVE-2006-2776","CVE-2006-2777","CVE-2006-2778","CVE-2006-2779","CVE-2006-2780","CVE-2006-2782","CVE-2006-2783","CVE-2006-2784","CVE-2006-2785","CVE-2006-2786","CVE-2006-2787","CVE-2006-2788");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "firefox", pkgver: "1.0.8-0ubuntu5.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to firefox-1.0.8-0ubuntu5.10.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "firefox-dev", pkgver: "1.0.8-0ubuntu5.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to firefox-dev-1.0.8-0ubuntu5.10.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "firefox-dom-inspector", pkgver: "1.0.8-0ubuntu5.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-dom-inspector-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to firefox-dom-inspector-1.0.8-0ubuntu5.10.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "firefox-gnome-support", pkgver: "1.0.8-0ubuntu5.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-gnome-support-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to firefox-gnome-support-1.0.8-0ubuntu5.10.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-firefox", pkgver: "1.0.8-0ubuntu5.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-firefox-1.0.8-0ubuntu5.10.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-firefox-dev", pkgver: "1.0.8-0ubuntu5.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-firefox-dev-1.0.8-0ubuntu5.10.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-firefox-dom-inspector", pkgver: "1.0.8-0ubuntu5.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-dom-inspector-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-firefox-dom-inspector-1.0.8-0ubuntu5.04.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-firefox-gnome-support", pkgver: "1.0.8-0ubuntu5.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-gnome-support-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-firefox-gnome-support-1.0.8-0ubuntu5.04.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
