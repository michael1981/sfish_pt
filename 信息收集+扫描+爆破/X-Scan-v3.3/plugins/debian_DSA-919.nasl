# This script was automatically generated from the dsa-919
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22785);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "919");
 script_bugtraq_id(15102);
 script_bugtraq_id(15756);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-919 security update');
 script_set_attribute(attribute: 'description', value:
'The upstream developer of curl, a multi-protocol file transfer
library, informed us that the former correction to several off-by-one
errors are not sufficient.  For completeness please find the original
bug description below:
Several problems were discovered in libcurl, a multi-protocol file
transfer library.  The Common Vulnerabilities and Exposures project
identifies the following problems:
CVE-2005-3185
    A buffer overflow has been discovered in libcurl
    that could allow the execution of arbitrary code.
CVE-2005-4077
    Stefan Esser discovered several off-by-one errors that allows
    local users to trigger a buffer overflow and cause a denial of
    service or bypass PHP security restrictions via certain URLs.
For the old stable distribution (woody) these problems have been fixed in
version 7.9.5-1woody2.
For the stable distribution (sarge) these problems have been fixed in
version 7.13.2-2sarge5.  This update also includes a bugfix against
data corruption.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-919');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libcurl packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA919] DSA-919-2 curl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_cve_id("CVE-2005-3185", "CVE-2005-4077");
 script_summary(english: "DSA-919-2 curl");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'curl', release: '3.0', reference: '7.9.5-1woody2');
deb_check(prefix: 'libcurl-dev', release: '3.0', reference: '7.9.5-1woody2');
deb_check(prefix: 'libcurl2', release: '3.0', reference: '7.9.5-1woody2');
deb_check(prefix: 'curl', release: '3.1', reference: '7.13.2-2sarge5');
deb_check(prefix: 'libcurl3', release: '3.1', reference: '7.13.2-2sarge5');
deb_check(prefix: 'libcurl3-dbg', release: '3.1', reference: '7.13.2-2sarge5');
deb_check(prefix: 'libcurl3-dev', release: '3.1', reference: '7.13.2-2sarge5');
deb_check(prefix: 'libcurl3-gssapi', release: '3.1', reference: '7.13.2-2sarge5');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
