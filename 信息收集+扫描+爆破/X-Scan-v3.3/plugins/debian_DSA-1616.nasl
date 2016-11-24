# This script was automatically generated from the dsa-1616
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(33568);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "1616");
 script_cve_id("CVE-2008-2713", "CVE-2008-3215");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1616 security update');
 script_set_attribute(attribute: 'description', value:
'Damian Put discovered a vulnerability in the ClamAV anti-virus
toolkit\'s parsing of Petite-packed Win32 executables.  The weakness
leads to an invalid memory access, and could enable an attacker to
crash clamav by supplying a maliciously crafted Petite-compressed
binary for scanning.  In some configurations, such as when clamav
is used in combination with mail servers, this could cause a system
to <q>fail open</q>, facilitating a follow-on viral attack.
A previous version of this advisory referenced packages that were
built incorrectly and omitted the intended correction.  This
issue was fixed in packages referenced by the -2 revision of the
advisory.
The Common Vulnerabilities and Exposures project identifies this
weakness as CVE-2008-2713
and CVE-2008-3215.
For the stable distribution (etch), this problem has been fixed in
version 0.90.1dfsg-3.1+etch14.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1616');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your clamav packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1616] DSA-1616-2 clamav");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1616-2 clamav");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'clamav', release: '4.0', reference: '0.90.1dfsg-3.1+etch14');
deb_check(prefix: 'clamav-base', release: '4.0', reference: '0.90.1dfsg-3.1+etch14');
deb_check(prefix: 'clamav-daemon', release: '4.0', reference: '0.90.1dfsg-3.1+etch14');
deb_check(prefix: 'clamav-dbg', release: '4.0', reference: '0.90.1dfsg-3.1+etch14');
deb_check(prefix: 'clamav-docs', release: '4.0', reference: '0.90.1dfsg-3.1+etch14');
deb_check(prefix: 'clamav-freshclam', release: '4.0', reference: '0.90.1dfsg-3.1+etch14');
deb_check(prefix: 'clamav-milter', release: '4.0', reference: '0.90.1dfsg-3.1+etch14');
deb_check(prefix: 'clamav-testfiles', release: '4.0', reference: '0.90.1dfsg-3.1+etch14');
deb_check(prefix: 'libclamav-dev', release: '4.0', reference: '0.90.1dfsg-3.1+etch14');
deb_check(prefix: 'libclamav2', release: '4.0', reference: '0.90.1dfsg-3.1+etch14');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
