# This script was automatically generated from the dsa-1224
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(23766);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1224");
 script_cve_id("CVE-2006-4310", "CVE-2006-5462", "CVE-2006-5463", "CVE-2006-5464", "CVE-2006-5748");
 script_bugtraq_id(19678, 20957);
 script_xref(name: "CERT", value: "335392");
 script_xref(name: "CERT", value: "390480");
 script_xref(name: "CERT", value: "495288");
 script_xref(name: "CERT", value: "714496");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1224 security update');
 script_set_attribute(attribute: 'description', value:
'Several security related problems have been discovered in Mozilla and
derived products.  The Common Vulnerabilities and Exposures project
identifies the following vulnerabilities:
CVE-2006-4310
    Tomas Kempinsky discovered that malformed FTP server responses
    could lead to denial of service.
CVE-2006-5462
    Ulrich Kühn discovered that the correction for a cryptographic
    flaw in the handling of PKCS-1 certificates was incomplete, which
    allows the forgery of certificates.
CVE-2006-5463
    <q>shutdown</q> discovered that modification of JavaScript objects
    during execution could lead to the execution of arbitrary
    JavaScript bytecode.
CVE-2006-5464
    Jesse Ruderman and Martijn Wargers discovered several crashes in
    the layout engine, which might also allow execution of arbitrary
    code.
CVE-2006-5748
    Igor Bukanov and Jesse Ruderman discovered several crashes in the
    JavaScript engine, which might allow execution of arbitrary code.
This update also addresses several crashes, which could be triggered by
malicious websites and fixes a regression introduced in the previous
Mozilla update.
For the stable distribution (sarge) these problems have been fixed in
version 1.7.8-1sarge8.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1224');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mozilla package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1224] DSA-1224-1 mozilla");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1224-1 mozilla");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libnspr-dev', release: '3.1', reference: '1.7.8-1sarge8');
deb_check(prefix: 'libnspr4', release: '3.1', reference: '1.7.8-1sarge8');
deb_check(prefix: 'libnss-dev', release: '3.1', reference: '1.7.8-1sarge8');
deb_check(prefix: 'libnss3', release: '3.1', reference: '1.7.8-1sarge8');
deb_check(prefix: 'mozilla', release: '3.1', reference: '1.7.8-1sarge8');
deb_check(prefix: 'mozilla-browser', release: '3.1', reference: '1.7.8-1sarge8');
deb_check(prefix: 'mozilla-calendar', release: '3.1', reference: '1.7.8-1sarge8');
deb_check(prefix: 'mozilla-chatzilla', release: '3.1', reference: '1.7.8-1sarge8');
deb_check(prefix: 'mozilla-dev', release: '3.1', reference: '1.7.8-1sarge8');
deb_check(prefix: 'mozilla-dom-inspector', release: '3.1', reference: '1.7.8-1sarge8');
deb_check(prefix: 'mozilla-js-debugger', release: '3.1', reference: '1.7.8-1sarge8');
deb_check(prefix: 'mozilla-mailnews', release: '3.1', reference: '1.7.8-1sarge8');
deb_check(prefix: 'mozilla-psm', release: '3.1', reference: '1.7.8-1sarge8');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
