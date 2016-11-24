# This script was automatically generated from the dsa-920
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22786);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "920");
 script_cve_id("CVE-2005-3651");
 script_bugtraq_id(15794);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-920 security update');
 script_set_attribute(attribute: 'description', value:
'A buffer overflow has been discovered in ethereal, a commonly used
network traffic analyser that causes a denial of service and may
potentially allow the execution of arbitrary code.
For the old stable distribution (woody) this problem has been fixed in
version 0.9.4-1woody14.
For the stable distribution (sarge) this problem has been fixed in
version 0.10.10-2sarge3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-920');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your ethereal packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA920] DSA-920-1 ethereal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-920-1 ethereal");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ethereal', release: '3.0', reference: '0.9.4-1woody14');
deb_check(prefix: 'ethereal-common', release: '3.0', reference: '0.9.4-1woody14');
deb_check(prefix: 'ethereal-dev', release: '3.0', reference: '0.9.4-1woody14');
deb_check(prefix: 'tethereal', release: '3.0', reference: '0.9.4-1woody14');
deb_check(prefix: 'ethereal', release: '3.1', reference: '0.10.10-2sarge4');
deb_check(prefix: 'ethereal-common', release: '3.1', reference: '0.10.10-2sarge4');
deb_check(prefix: 'ethereal-dev', release: '3.1', reference: '0.10.10-2sarge4');
deb_check(prefix: 'tethereal', release: '3.1', reference: '0.10.10-2sarge4');
deb_check(prefix: 'ethereal', release: '3.1', reference: '0.10.10-2sarge3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
