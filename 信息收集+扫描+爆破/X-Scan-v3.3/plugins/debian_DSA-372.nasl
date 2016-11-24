# This script was automatically generated from the dsa-372
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15209);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "372");
 script_cve_id("CVE-2003-0685");
 script_bugtraq_id(8400);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-372 security update');
 script_set_attribute(attribute: 'description', value:
'Shaun Colley discovered a buffer overflow vulnerability in netris, a
network version of a popular puzzle game.  A netris client connecting
to an untrusted netris server could be sent an unusually long data
packet, which would be copied into a fixed-length buffer without
bounds checking.  This vulnerability could be exploited to gain the
privileges of the user running netris in client mode, if they connect
to a hostile netris server.
For the current stable distribution (woody) this problem has been fixed
in version 0.5-4woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-372');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-372
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA372] DSA-372-1 netris");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-372-1 netris");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'netris', release: '3.0', reference: '0.5-4woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
