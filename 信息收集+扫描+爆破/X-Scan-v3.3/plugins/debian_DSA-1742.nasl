# This script was automatically generated from the dsa-1742
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35925);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1742");
 script_cve_id("CVE-2009-0186");
 script_bugtraq_id(33963);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1742 security update');
 script_set_attribute(attribute: 'description', value:
'Alan Rad Pop discovered that libsndfile, a library to read and write
sampled audio data, is prone to an integer overflow. This causes a
heap-based buffer overflow when processing crafted CAF description
chunks possibly leading to arbitrary code execution.
For the oldstable distribution (etch) this problem has been fixed in
version 1.0.16-2+etch1.
For the stable distribution (lenny) this problem has been fixed in
version 1.0.17-4+lenny1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1742');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libsndfile packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1742] DSA-1742-1 libsndfile");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1742-1 libsndfile");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libsndfile1', release: '4.0', reference: '1.0.16-2+etch1');
deb_check(prefix: 'libsndfile1-dev', release: '4.0', reference: '1.0.16-2+etch1');
deb_check(prefix: 'sndfile-programs', release: '4.0', reference: '1.0.16-2+etch1');
deb_check(prefix: 'libsndfile1', release: '5.0', reference: '1.0.17-4+lenny1');
deb_check(prefix: 'libsndfile1-dev', release: '5.0', reference: '1.0.17-4+lenny1');
deb_check(prefix: 'sndfile-programs', release: '5.0', reference: '1.0.17-4+lenny1');
deb_check(prefix: 'libsndfile', release: '4.0', reference: '1.0.16-2+etch1');
deb_check(prefix: 'libsndfile', release: '5.0', reference: '1.0.17-4+lenny1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
