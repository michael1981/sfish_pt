# This script was automatically generated from the dsa-1821
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(39483);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1821");
 script_cve_id("CVE-2009-1440");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1821 security update');
 script_set_attribute(attribute: 'description', value:
'Sam Hocevar discovered that amule, a client for the eD2k and Kad
networks, does not properly sanitise the filename, when using the
preview function. This could lead to the injection of arbitrary commands
passed to the video player.
The oldstable distribution (etch) is not affected by this issue.
For the stable distribution (lenny), this problem has been fixed in
version 2.2.1-1+lenny2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1821');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your amule packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1821] DSA-1821-1 amule");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1821-1 amule");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'amule', release: '5.0', reference: '2.2.1-1+lenny2');
deb_check(prefix: 'amule-common', release: '5.0', reference: '2.2.1-1+lenny2');
deb_check(prefix: 'amule-daemon', release: '5.0', reference: '2.2.1-1+lenny2');
deb_check(prefix: 'amule-utils', release: '5.0', reference: '2.2.1-1+lenny2');
deb_check(prefix: 'amule-utils-gui', release: '5.0', reference: '2.2.1-1+lenny2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
