# This script was automatically generated from the 297-3 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27872);
script_version("$Revision: 1.4 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "297-3");
script_summary(english:"Thunderbird vulnerabilities");
script_name(english:"USN297-3 : Thunderbird vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- mozilla-thunderbird 
- mozilla-thunderbird-dev 
- mozilla-thunderbird-inspector 
- mozilla-thunderbird-offline 
- mozilla-thunderbird-typeaheadfind 
');
script_set_attribute(attribute:'description', value: 'USN-297-1 fixed several vulnerabilities in Thunderbird for the Ubuntu
6.06 LTS release. This update provides the corresponding fixes for
Ubuntu 5.04 and Ubuntu 5.10.

For reference, these are the details of the original USN:

  Jonas Sicking discovered that under some circumstances persisted XUL
  attributes are associated with the wrong URL. A malicious web site
  could exploit this to execute arbitrary code with the privileges of
  the user. (MFSA 2006-35, CVE-2006-2775)

  Paul Nickerson discovered that content-defined setters on an object
  prototype were getting called by privileged UI code. It was
  demonstrated that this could be exploited to run arbitrary web
  script with full user privileges (MFSA 2006-37, CVE-2006-2776).

  Mikolaj Habryn discovered a buffer overflow in the crypto.signText()
  function. By sending an email with malicious JavaScript to an user,
  and that user enabled JavaScript in Thunderbird (which is not the
  default and not recommended), this could potentially be exploited to

[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- mozilla-thunderbird-1.0.8-0ubuntu05.10.2 (Ubuntu 5.10)
- mozilla-thunderbird-dev-1.0.8-0ubuntu05.10.2 (Ubuntu 5.10)
- mozilla-thunderbird-inspector-1.0.8-0ubuntu05.10.2 (Ubuntu 5.10)
- mozilla-thunderbird-offline-1.0.8-0ubuntu05.10.2 (Ubuntu 5.10)
- mozilla-thunderbird-typeaheadfind-1.0.8-0ubuntu05.10.2 (Ubuntu 5.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2006-2775","CVE-2006-2776","CVE-2006-2778","CVE-2006-2779","CVE-2006-2780","CVE-2006-2781","CVE-2006-2783","CVE-2006-2784","CVE-2006-2786","CVE-2006-2787");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "mozilla-thunderbird", pkgver: "1.0.8-0ubuntu05.10.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-thunderbird-1.0.8-0ubuntu05.10.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-thunderbird-dev", pkgver: "1.0.8-0ubuntu05.10.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-thunderbird-dev-1.0.8-0ubuntu05.10.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-thunderbird-inspector", pkgver: "1.0.8-0ubuntu05.10.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-inspector-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-thunderbird-inspector-1.0.8-0ubuntu05.10.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-thunderbird-offline", pkgver: "1.0.8-0ubuntu05.10.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-offline-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-thunderbird-offline-1.0.8-0ubuntu05.10.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-thunderbird-typeaheadfind", pkgver: "1.0.8-0ubuntu05.10.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-typeaheadfind-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-thunderbird-typeaheadfind-1.0.8-0ubuntu05.10.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
