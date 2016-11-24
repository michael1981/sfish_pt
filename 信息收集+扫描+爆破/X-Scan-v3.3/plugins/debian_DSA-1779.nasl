# This script was automatically generated from the dsa-1779
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(38158);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1779");
 script_cve_id("CVE-2009-1300", "CVE-2009-1358");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1779 security update');
 script_set_attribute(attribute: 'description', value:
'Two vulnerabilities have been discovered in APT, the well-known dpkg
frontend. The Common Vulnerabilities and Exposures project identifies
the following problems:
CVE-2009-1300
    In time zones where daylight savings time occurs at midnight,
    the apt cron.daily script fails, stopping new security updates
    from being applied automatically.
CVE-2009-1358
    A repository that has been signed with an expired or revoked
    OpenPGP key would still be considered valid by APT.
For the old stable distribution (etch), these problems have been fixed in
version 0.6.46.4-0.1+etch1.
For the stable distribution (lenny), these problems have been fixed in
version 0.7.20.2+lenny1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1779');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your apt package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1779] DSA-1779-1 apt");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1779-1 apt");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'apt', release: '4.0', reference: '0.6.46.4-0.1+etch1');
deb_check(prefix: 'apt-doc', release: '4.0', reference: '0.6.46.4-0.1+etch1');
deb_check(prefix: 'apt-utils', release: '4.0', reference: '0.6.46.4-0.1+etch1');
deb_check(prefix: 'libapt-pkg-dev', release: '4.0', reference: '0.6.46.4-0.1+etch1');
deb_check(prefix: 'libapt-pkg-doc', release: '4.0', reference: '0.6.46.4-0.1+etch1');
deb_check(prefix: 'apt', release: '5.0', reference: '0.7.20.2+lenny1');
deb_check(prefix: 'apt-doc', release: '5.0', reference: '0.7.20.2+lenny1');
deb_check(prefix: 'apt-transport-https', release: '5.0', reference: '0.7.20.2+lenny1');
deb_check(prefix: 'apt-utils', release: '5.0', reference: '0.7.20.2+lenny1');
deb_check(prefix: 'libapt-pkg-dev', release: '5.0', reference: '0.7.20.2+lenny1');
deb_check(prefix: 'libapt-pkg-doc', release: '5.0', reference: '0.7.20.2+lenny1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
