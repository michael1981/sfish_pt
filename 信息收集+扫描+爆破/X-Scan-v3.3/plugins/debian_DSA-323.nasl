# This script was automatically generated from the dsa-323
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15160);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "323");
 script_cve_id("CVE-2003-0381");
 script_bugtraq_id(7937);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-323 security update');
 script_set_attribute(attribute: 'description', value:
'Jakob Lell discovered a bug in the \'noroff\' script included in noweb
whereby a temporary file was created insecurely.  During a review,
several other instances of this problem were found and fixed.  Any of
these bugs could be exploited by a local user to overwrite arbitrary
files owned by the user invoking the script.
For the stable distribution (woody) these problems have been fixed in
version 2.9a-7.3.
For old stable distribution (potato) this problem has been fixed in
version 2.9a-5.1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-323');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-323
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA323] DSA-323-1 noweb");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-323-1 noweb");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'nowebm', release: '2.2', reference: '2.9a-5.1');
deb_check(prefix: 'nowebm', release: '3.0', reference: '2.9a-7.3');
deb_check(prefix: 'noweb', release: '3.0', reference: '2.9a-7.3');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
