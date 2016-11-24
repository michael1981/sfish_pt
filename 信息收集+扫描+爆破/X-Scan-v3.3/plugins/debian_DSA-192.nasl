# This script was automatically generated from the dsa-192
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15029);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "192");
 script_cve_id("CVE-2002-1275");
 script_bugtraq_id(6079);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-192 security update');
 script_set_attribute(attribute: 'description', value:
'The SuSE Security Team found a vulnerability in html2ps, an HTML to
PostScript converter, that opened files based on unsanitized input
insecurely.  This problem can be exploited when html2ps is installed
as filter within lprng and the attacker has previously gained access
to the lp account.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-192');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your html2ps package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA192] DSA-192-1 html2ps");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-192-1 html2ps");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'html2ps', release: '2.2', reference: '1.0b1-8.2');
deb_check(prefix: 'html2ps', release: '3.0', reference: '1.0b3-1.2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
