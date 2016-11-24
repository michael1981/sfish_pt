# This script was automatically generated from the dsa-072
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14909);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "072");
 script_cve_id("CVE-2001-1022");
 script_bugtraq_id(3103);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-072 security update');
 script_set_attribute(attribute: 'description', value:
'Zenith Parse found a security problem in groff (the GNU version of
troff). The pic command was vulnerable to a printf format attack
which made it possible to circumvent the `-S\' option and execute
arbitrary code.

This has been fixed in version 1.15.2-2, and we recommend that you upgrade
your groff packages immediately.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-072');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-072
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA072] DSA-072-1 groff");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-072-1 groff");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'groff', release: '2.2', reference: '1.15.2-2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
