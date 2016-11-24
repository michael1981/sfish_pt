# This script was automatically generated from the 313-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27889);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "313-2");
script_summary(english:"openoffice.org2-amd64, openoffice.org2 vulnerabilities");
script_name(english:"USN313-2 : openoffice.org2-amd64, openoffice.org2 vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- mozilla-openoffice.org 
- openoffice.org2 
- openoffice.org2-base 
- openoffice.org2-calc 
- openoffice.org2-common 
- openoffice.org2-core 
- openoffice.org2-dev 
- openoffice.org2-dev-doc 
- openoffice.org2-draw 
- openoffice.org2-evolution 
- openoffice.org2-filter-so52 
- openoffice.org2-gnome 
- openoffice.org2-impress 
- openoffice.org2-java-common 
- openoffice.org2-kde 
- openoffice.org2-l10n-en-us 
- openoffice.org2-math 
- openoffice.org2-off
[...]');
script_set_attribute(attribute:'description', value: 'USN-313-1 fixed several vulnerabilities in OpenOffice for Ubuntu 5.04 and
Ubuntu 6.06 LTS. This followup advisory provides the corresponding
update for Ubuntu 5.10.

For reference, these are the details of the original USN:

  It was possible to embed Basic macros in documents in a way that
  OpenOffice.org would not ask for confirmation about executing them. By
  tricking a user into opening a malicious document, this could be
  exploited to run arbitrary Basic code (including local file access and
  modification) with the user\'s privileges. (CVE-2006-2198)
  
  A flaw was discovered in the Java sandbox which allowed Java applets
  to break out of the sandbox and execute code without restrictions.  By
  tricking a user into opening a malicious document, this could be
  exploited to run arbitrary code with the user\'s privileges. This
  update disables Java applets for OpenOffice.org, since it is not
  generally possible to guarantee the sandbox restrictions.
  (CVE-2006-2199)
  
  A buffer overflow has bee
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- mozilla-openoffice.org-1.9.129-0.1ubuntu4.1 (Ubuntu 5.10)
- openoffice.org2-1.9.129-0.1ubuntu4.1 (Ubuntu 5.10)
- openoffice.org2-base-1.9.129-0.1ubuntu4.1 (Ubuntu 5.10)
- openoffice.org2-calc-1.9.129-0.1ubuntu4.1 (Ubuntu 5.10)
- openoffice.org2-common-1.9.129-0.1ubuntu4.1 (Ubuntu 5.10)
- openoffice.org2-core-1.9.129-0.1ubuntu4.1 (Ubuntu 5.10)
- openoffice.org2-dev-1.9.129-0.1ubuntu4.1 (Ubuntu 5.10)
- openoffice.org2-dev-doc-1.9.129-0.1ubuntu4.1 (Ubuntu 5.10)
- openoffice.org2-draw-1.9.129-0
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2006-2198","CVE-2006-2199","CVE-2006-3117");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "mozilla-openoffice.org", pkgver: "1.9.129-0.1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-openoffice.org-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-openoffice.org-1.9.129-0.1ubuntu4.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "openoffice.org2", pkgver: "1.9.129-0.1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org2-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to openoffice.org2-1.9.129-0.1ubuntu4.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "openoffice.org2-base", pkgver: "1.9.129-0.1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org2-base-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to openoffice.org2-base-1.9.129-0.1ubuntu4.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "openoffice.org2-calc", pkgver: "1.9.129-0.1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org2-calc-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to openoffice.org2-calc-1.9.129-0.1ubuntu4.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "openoffice.org2-common", pkgver: "1.9.129-0.1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org2-common-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to openoffice.org2-common-1.9.129-0.1ubuntu4.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "openoffice.org2-core", pkgver: "1.9.129-0.1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org2-core-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to openoffice.org2-core-1.9.129-0.1ubuntu4.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "openoffice.org2-dev", pkgver: "1.9.129-0.1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org2-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to openoffice.org2-dev-1.9.129-0.1ubuntu4.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "openoffice.org2-dev-doc", pkgver: "1.9.129-0.1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org2-dev-doc-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to openoffice.org2-dev-doc-1.9.129-0.1ubuntu4.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "openoffice.org2-draw", pkgver: "1.9.129-0.1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org2-draw-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to openoffice.org2-draw-1.9.129-0.1ubuntu4.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "openoffice.org2-evolution", pkgver: "1.9.129-0.1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org2-evolution-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to openoffice.org2-evolution-1.9.129-0.1ubuntu4.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "openoffice.org2-filter-so52", pkgver: "1.9.129-0.1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org2-filter-so52-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to openoffice.org2-filter-so52-1.9.129-0.1ubuntu4.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "openoffice.org2-gnome", pkgver: "1.9.129-0.1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org2-gnome-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to openoffice.org2-gnome-1.9.129-0.1ubuntu4.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "openoffice.org2-impress", pkgver: "1.9.129-0.1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org2-impress-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to openoffice.org2-impress-1.9.129-0.1ubuntu4.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "openoffice.org2-java-common", pkgver: "1.9.129-0.1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org2-java-common-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to openoffice.org2-java-common-1.9.129-0.1ubuntu4.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "openoffice.org2-kde", pkgver: "1.9.129-0.1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org2-kde-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to openoffice.org2-kde-1.9.129-0.1ubuntu4.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "openoffice.org2-l10n-en-us", pkgver: "1.9.129-0.1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org2-l10n-en-us-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to openoffice.org2-l10n-en-us-1.9.129-0.1ubuntu4.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "openoffice.org2-math", pkgver: "1.9.129-0.1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org2-math-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to openoffice.org2-math-1.9.129-0.1ubuntu4.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "openoffice.org2-officebean", pkgver: "1.9.129-0.1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org2-officebean-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to openoffice.org2-officebean-1.9.129-0.1ubuntu4.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "openoffice.org2-writer", pkgver: "1.9.129-0.1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openoffice.org2-writer-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to openoffice.org2-writer-1.9.129-0.1ubuntu4.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "python-uno", pkgver: "1.9.129-0.1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python-uno-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to python-uno-1.9.129-0.1ubuntu4.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "ttf-opensymbol", pkgver: "1.9.129-0.1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ttf-opensymbol-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to ttf-opensymbol-1.9.129-0.1ubuntu4.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
