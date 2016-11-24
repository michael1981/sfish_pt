# This script was automatically generated from the dsa-1512
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(31359);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1512");
 script_cve_id("CVE-2008-0072");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1512 security update');
 script_set_attribute(attribute: 'description', value:
'Ulf H&auml;rnhammar discovered that Evolution, the e-mail and groupware suite,
had a format string vulnerability in the parsing of encrypted mail messages.
If the user opened a specially crafted email message, code execution was
possible.
For the stable distribution (etch), this problem has been fixed in version
2.6.3-6etch2.
For the old stable distribution (sarge), this problem has been fixed in
version 2.0.4-2sarge3. Some architectures have not yet completed building
the updated package for sarge, they will be added as they come available.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1512');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your evolution package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1512] DSA-1512-1 evolution");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1512-1 evolution");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'evolution', release: '3.1', reference: '2.0.4-2sarge3');
deb_check(prefix: 'evolution-dev', release: '3.1', reference: '2.0.4-2sarge3');
deb_check(prefix: 'evolution', release: '4.0', reference: '2.6.3-6etch2');
deb_check(prefix: 'evolution-common', release: '4.0', reference: '2.6.3-6etch2');
deb_check(prefix: 'evolution-dbg', release: '4.0', reference: '2.6.3-6etch2');
deb_check(prefix: 'evolution-dev', release: '4.0', reference: '2.6.3-6etch2');
deb_check(prefix: 'evolution-plugins', release: '4.0', reference: '2.6.3-6etch2');
deb_check(prefix: 'evolution-plugins-experimental', release: '4.0', reference: '2.6.3-6etch2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
