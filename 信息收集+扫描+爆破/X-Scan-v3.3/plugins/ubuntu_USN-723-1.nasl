# This script was automatically generated from the 723-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(36720);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "723-1");
script_summary(english:"git-core vulnerabilities");
script_name(english:"USN723-1 : git-core vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- git-arch 
- git-core 
- git-cvs 
- git-daemon-run 
- git-doc 
- git-email 
- git-gui 
- git-p4 
- git-svn 
- gitk 
- gitweb 
');
script_set_attribute(attribute:'description', value: 'It was discovered that Git did not properly handle long file paths. If a user
were tricked into performing commands on a specially crafted Git repository, an
attacker could possibly execute arbitrary code with the privileges of the user
invoking the program. (CVE-2008-3546)

It was discovered that the Git web interface (gitweb) did not correctly handle
shell metacharacters when processing certain commands. A remote attacker could
send specially crafted commands to the Git server and execute arbitrary code
with the privileges of the Git web server. This issue only applied to Ubuntu
7.10 and 8.04 LTS. (CVE-2008-5516, CVE-2008-5517)

It was discovered that the Git web interface (gitweb) did not properly restrict
the diff.external configuration parameter. A local attacker could exploit this
issue and execute arbitrary code with the privileges of the Git web server.
This issue only applied to Ubuntu 8.04 LTS and 8.10. (CVE-2008-5916)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- git-arch-1.5.6.3-1.1ubuntu2.1 (Ubuntu 8.10)
- git-core-1.5.6.3-1.1ubuntu2.1 (Ubuntu 8.10)
- git-cvs-1.5.6.3-1.1ubuntu2.1 (Ubuntu 8.10)
- git-daemon-run-1.5.6.3-1.1ubuntu2.1 (Ubuntu 8.10)
- git-doc-1.5.6.3-1.1ubuntu2.1 (Ubuntu 8.10)
- git-email-1.5.6.3-1.1ubuntu2.1 (Ubuntu 8.10)
- git-gui-1.5.6.3-1.1ubuntu2.1 (Ubuntu 8.10)
- git-p4-1.5.2.5-2ubuntu0.1 (Ubuntu 7.10)
- git-svn-1.5.6.3-1.1ubuntu2.1 (Ubuntu 8.10)
- gitk-1.5.6.3-1.1ubuntu2.1 (Ubuntu 8.10)
- gitweb-1.5.6.3-1.1ubuntu2.1 (Ubuntu 8.10
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2008-3546","CVE-2008-5516","CVE-2008-5517","CVE-2008-5916");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "git-arch", pkgver: "1.5.6.3-1.1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package git-arch-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to git-arch-1.5.6.3-1.1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "git-core", pkgver: "1.5.6.3-1.1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package git-core-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to git-core-1.5.6.3-1.1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "git-cvs", pkgver: "1.5.6.3-1.1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package git-cvs-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to git-cvs-1.5.6.3-1.1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "git-daemon-run", pkgver: "1.5.6.3-1.1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package git-daemon-run-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to git-daemon-run-1.5.6.3-1.1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "git-doc", pkgver: "1.5.6.3-1.1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package git-doc-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to git-doc-1.5.6.3-1.1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "git-email", pkgver: "1.5.6.3-1.1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package git-email-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to git-email-1.5.6.3-1.1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "git-gui", pkgver: "1.5.6.3-1.1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package git-gui-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to git-gui-1.5.6.3-1.1ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "git-p4", pkgver: "1.5.2.5-2ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package git-p4-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to git-p4-1.5.2.5-2ubuntu0.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "git-svn", pkgver: "1.5.6.3-1.1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package git-svn-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to git-svn-1.5.6.3-1.1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "gitk", pkgver: "1.5.6.3-1.1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gitk-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to gitk-1.5.6.3-1.1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "gitweb", pkgver: "1.5.6.3-1.1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gitweb-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to gitweb-1.5.6.3-1.1ubuntu2.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
