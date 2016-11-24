# This script was automatically generated from the dsa-743
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(18651);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "743");
 script_cve_id("CVE-2005-1545", "CVE-2005-1546");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-743 security update');
 script_set_attribute(attribute: 'description', value:
'Several problems have been discovered in ht, a viewer, editor and
analyser for various executables, that may lead to the execution of
arbitrary code.  The Common Vulnerabilities and Exposures project
identifies the following problems:
    Tavis Ormandy of the Gentoo Linux Security Team discovered an
    integer overflow in the ELF parser.
    The authors have discovered a buffer overflow in the PE parser.
For the old stable distribution (woody) these problems have been fixed
in version 0.5.0-1woody4.  For the HP Precision architecture, you are
advised not to use this package anymore since we cannot provide
updated packages as it doesn\'t compile anymore.
For the stable distribution (sarge) these problems have been fixed in
version 0.8.0-2sarge4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-743');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your ht package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA743] DSA-743-1 ht");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-743-1 ht");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ht', release: '3.0', reference: '0.5.0-1woody4');
deb_check(prefix: 'ht', release: '3.1', reference: '0.8.0-2sarge4');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
