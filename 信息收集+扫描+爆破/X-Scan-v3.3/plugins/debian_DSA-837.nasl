# This script was automatically generated from the dsa-837
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19806);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "837");
 script_cve_id("CVE-2005-2871");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-837 security update');
 script_set_attribute(attribute: 'description', value:
'Tom Ferris discovered a bug in the IDN hostname handling of Mozilla
Firefox, which is also present in the other browsers from the same
family that allows remote attackers to cause a denial of service and
possibly execute arbitrary code via a hostname with dashes.
For the stable distribution (sarge) this problem has been fixed in
version 1.0.4-2sarge4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-837');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mozilla-firefox package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA837] DSA-837-1 mozilla-firefox");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-837-1 mozilla-firefox");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'mozilla-firefox', release: '3.1', reference: '1.0.4-2sarge4');
deb_check(prefix: 'mozilla-firefox-dom-inspector', release: '3.1', reference: '1.0.4-2sarge4');
deb_check(prefix: 'mozilla-firefox-gnome-support', release: '3.1', reference: '1.0.4-2sarge4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
