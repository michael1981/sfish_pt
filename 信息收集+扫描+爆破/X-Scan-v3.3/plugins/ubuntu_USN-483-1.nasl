# This script was automatically generated from the 483-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28084);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "483-1");
script_summary(english:"libnet-dns-perl vulnerabilities");
script_name(english:"USN483-1 : libnet-dns-perl vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'The remote package "libnet-dns-perl" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Peter Johannes Holzer discovered that the Net::DNS Perl module had
predictable sequence numbers.  This could allow remote attackers to
carry out DNS spoofing, leading to possible man-in-the-middle attacks.
(CVE-2007-3377)

Steffen Ullrich discovered that the Net::DNS Perl module did not correctly
detect recursive compressed responses.  A remote attacker could send a
specially crafted packet, causing applications using Net::DNS to crash or
monopolize CPU resources, leading to a denial of service.  (CVE-2007-3409)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libnet-dns-perl-0.57-1ubuntu1 (Ubuntu 6.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2007-3377","CVE-2007-3409");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "libnet-dns-perl", pkgver: "0.57-1ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnet-dns-perl-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libnet-dns-perl-0.57-1ubuntu1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
