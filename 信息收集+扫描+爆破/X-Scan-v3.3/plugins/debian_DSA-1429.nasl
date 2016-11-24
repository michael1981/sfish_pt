# This script was automatically generated from the dsa-1429
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(29337);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1429");
 script_cve_id("CVE-2007-6110");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1429 security update');
 script_set_attribute(attribute: 'description', value:
'Michael Skibbe discovered that htdig, a WWW search system for an intranet
or small internet, did not adequately quote values submitted to the search
script, allowing remote attackers to inject arbitrary script or HTML
into specially crafted links.
For the old stable distribution (sarge), this problem was not present.
For the stable distribution (etch), this problem has been fixed in version
1:3.2.0b6-3.1etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1429');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your htdig package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1429] DSA-1429-1 htdig");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1429-1 htdig");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'htdig', release: '4.0', reference: '3.2.0b6-3.1etch1');
deb_check(prefix: 'htdig-doc', release: '4.0', reference: '3.2.0b6-3.1etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
