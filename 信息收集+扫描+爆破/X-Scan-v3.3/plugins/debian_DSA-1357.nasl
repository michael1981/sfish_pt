# This script was automatically generated from the dsa-1357
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25937);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1357");
 script_cve_id("CVE-2007-3387");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1357 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that an integer overflow in the xpdf PDF viewer may lead
to the execution of arbitrary code if a malformed PDF file is opened.
koffice includes a copy of the xpdf code and required an update as well.
The oldstable distribution (sarge) will be fixed later.
For the stable distribution (etch) this problem has been fixed in
version 1.6.1-2etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1357');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your koffice packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1357] DSA-1357-1 koffice");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1357-1 koffice");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'karbon', release: '4.0', reference: '1.6.1-2etch1');
deb_check(prefix: 'kchart', release: '4.0', reference: '1.6.1-2etch1');
deb_check(prefix: 'kexi', release: '4.0', reference: '1.6.1-2etch1');
deb_check(prefix: 'kformula', release: '4.0', reference: '1.6.1-2etch1');
deb_check(prefix: 'kivio', release: '4.0', reference: '1.6.1-2etch1');
deb_check(prefix: 'kivio-data', release: '4.0', reference: '1.6.1-2etch1');
deb_check(prefix: 'koffice', release: '4.0', reference: '1.6.1-2etch1');
deb_check(prefix: 'koffice-data', release: '4.0', reference: '1.6.1-2etch1');
deb_check(prefix: 'koffice-dbg', release: '4.0', reference: '1.6.1-2etch1');
deb_check(prefix: 'koffice-dev', release: '4.0', reference: '1.6.1-2etch1');
deb_check(prefix: 'koffice-doc', release: '4.0', reference: '1.6.1-2etch1');
deb_check(prefix: 'koffice-doc-html', release: '4.0', reference: '1.6.1-2etch1');
deb_check(prefix: 'koffice-libs', release: '4.0', reference: '1.6.1-2etch1');
deb_check(prefix: 'koshell', release: '4.0', reference: '1.6.1-2etch1');
deb_check(prefix: 'kplato', release: '4.0', reference: '1.6.1-2etch1');
deb_check(prefix: 'kpresenter', release: '4.0', reference: '1.6.1-2etch1');
deb_check(prefix: 'kpresenter-data', release: '4.0', reference: '1.6.1-2etch1');
deb_check(prefix: 'krita', release: '4.0', reference: '1.6.1-2etch1');
deb_check(prefix: 'krita-data', release: '4.0', reference: '1.6.1-2etch1');
deb_check(prefix: 'kspread', release: '4.0', reference: '1.6.1-2etch1');
deb_check(prefix: 'kthesaurus', release: '4.0', reference: '1.6.1-2etch1');
deb_check(prefix: 'kugar', release: '4.0', reference: '1.6.1-2etch1');
deb_check(prefix: 'kword', release: '4.0', reference: '1.6.1-2etch1');
deb_check(prefix: 'kword-data', release: '4.0', reference: '1.6.1-2etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
