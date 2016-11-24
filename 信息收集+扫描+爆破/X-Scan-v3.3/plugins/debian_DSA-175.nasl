# This script was automatically generated from the dsa-175
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15012);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "175");
 script_cve_id("CVE-2002-1200");
 script_bugtraq_id(5934);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-175 security update');
 script_set_attribute(attribute: 'description', value:
'Balazs Scheidler discovered a problem in the way syslog-ng handles macro
expansion.  When a macro is expanded a static length buffer is used
accompanied by a counter.  However, when constant characters are
appended, the counter is not updated properly, leading to incorrect
boundary checking.  An attacker may be able to use specially crafted
log messages inserted via UDP which overflows the buffer.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-175');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your syslog-ng package immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA175] DSA-175-1 syslog-ng");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-175-1 syslog-ng");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'syslog-ng', release: '2.2', reference: '1.4.0rc3-3.2');
deb_check(prefix: 'syslog-ng', release: '3.0', reference: '1.5.15-1.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
