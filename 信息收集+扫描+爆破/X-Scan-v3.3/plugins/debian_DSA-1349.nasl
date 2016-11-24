# This script was automatically generated from the dsa-1349
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25857);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1349");
 script_cve_id("CVE-2007-3387");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1349 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that an integer overflow in the xpdf PDF viewer may lead
to the execution of arbitrary code if a malformed PDF file is opened.
libextractor includes a copy of the xpdf code and required an update
as well.
For the oldstable distribution (sarge) this problem has been fixed in
version 0.4.2-2sarge6.
The stable distribution (etch) isn\'t affected by this problem.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1349');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libextractor packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1349] DSA-1349-1 libextractor");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1349-1 libextractor");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'extract', release: '3.1', reference: '0.4.2-2sarge6');
deb_check(prefix: 'libextractor1', release: '3.1', reference: '0.4.2-2sarge6');
deb_check(prefix: 'libextractor1-dev', release: '3.1', reference: '0.4.2-2sarge6');
deb_check(prefix: 'libextractor', release: '3.1', reference: '0.4.2-2sarge6');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
