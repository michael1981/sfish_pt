# This script was automatically generated from the dsa-162
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14999);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "162");
 script_cve_id("CVE-2002-0834");
 script_bugtraq_id(5573);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-162 security update');
 script_set_attribute(attribute: 'description', value:
'Ethereal developers discovered a buffer overflow in the ISIS protocol
dissector.  It may be possible to make Ethereal crash or hang by
injecting a purposefully malformed packet onto the wire, or by
convincing someone to read a malformed packet trace file.  It may be
possible to make Ethereal run arbitrary code by exploiting the buffer
and pointer problems.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-162');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your ethereal packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA162] DSA-162-1 ethereal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-162-1 ethereal");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ethereal', release: '2.2', reference: '0.8.0-4potato.1');
deb_check(prefix: 'ethereal', release: '3.0', reference: '0.9.4-1woody2');
deb_check(prefix: 'ethereal-common', release: '3.0', reference: '0.9.4-1woody2');
deb_check(prefix: 'ethereal-dev', release: '3.0', reference: '0.9.4-1woody2');
deb_check(prefix: 'tethereal', release: '3.0', reference: '0.9.4-1woody2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
