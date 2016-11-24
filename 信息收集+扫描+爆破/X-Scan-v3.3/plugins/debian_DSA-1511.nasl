# This script was automatically generated from the dsa-1511
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(31358);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1511");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1511 security update');
 script_set_attribute(attribute: 'description', value:
'Several local vulnerabilities have been discovered in libicu,
International Components for Unicode, The Common Vulnerabilities and
Exposures project identifies the following problems:
 
  libicu in International Components for Unicode (ICU) 3.8.1 and earlier
  attempts to process backreferences to the nonexistent capture group
  zero (aka \\0), which might allow context-dependent attackers to read
  from, or write to, out-of-bounds memory locations, related to
  corruption of REStackFrames.
 
  Heap-based buffer overflow in the doInterval function in regexcmp.cpp
  in libicu in International Components for Unicode (ICU) 3.8.1 and
  earlier allows context-dependent attackers to cause a denial of
  service (memory consumption) and possibly have unspecified other
  impact via a regular expression that writes a large amount of data to
  the backtracking stack.
For the stable distribution (etch), these problems have been fixed in
version 3.6-2etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1511');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libicu package.');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1511] DSA-1511-1 libicu");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1511-1 libicu");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'icu-doc', release: '4.0', reference: '3.6-2etch1');
deb_check(prefix: 'libicu36', release: '4.0', reference: '3.6-2etch1');
deb_check(prefix: 'libicu36-dev', release: '4.0', reference: '3.6-2etch1');
deb_check(prefix: 'libicu', release: '4.0', reference: '3.6-2etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
