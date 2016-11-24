# This script was automatically generated from the dsa-1814
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(39374);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1814");
 script_cve_id("CVE-2009-1788", "CVE-2009-1791");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1814 security update');
 script_set_attribute(attribute: 'description', value:
'Two vulnerabilities have been found in libsndfile, a library to read
and write sampled audio data.  The Common Vulnerabilities and Exposures
project identified the following problems:
CVE-2009-1788
Tobias Klein discovered that the VOC parsing routines suffer of a heap-based
buffer overflow which can be triggered by an attacker via a crafted VOC
header.
CVE-2009-1791
The vendor discovered that the  AIFF parsing routines suffer of a heap-based
buffer overflow similar to CVE-2009-1788 which can be triggered by an attacker
via a crafted AIFF header.
In both cases the overflowing data is not completely attacker controlled but
still leads to application crashes or under some circumstances might still
lead to arbitrary code execution.
For the oldstable distribution (etch), this problem has been fixed in
version 1.0.16-2+etch2.
For the stable distribution (lenny), this problem has been fixed in
version 1.0.17-4+lenny2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1814');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libsndfile packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1814] DSA-1814-1 libsndfile");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1814-1 libsndfile");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libsndfile1', release: '4.0', reference: '1.0.16-2+etch2');
deb_check(prefix: 'libsndfile1-dev', release: '4.0', reference: '1.0.16-2+etch2');
deb_check(prefix: 'sndfile-programs', release: '4.0', reference: '1.0.16-2+etch2');
deb_check(prefix: 'libsndfile1', release: '5.0', reference: '1.0.17-4+lenny2');
deb_check(prefix: 'libsndfile1-dev', release: '5.0', reference: '1.0.17-4+lenny2');
deb_check(prefix: 'sndfile-programs', release: '5.0', reference: '1.0.17-4+lenny2');
deb_check(prefix: 'libsndfile', release: '4.0', reference: '1.0.16-2+etch2');
deb_check(prefix: 'libsndfile', release: '5.0', reference: '1.0.17-4+lenny2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
