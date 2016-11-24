# This script was automatically generated from the dsa-1626
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(33775);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1626");
 script_cve_id("CVE-2008-3429");
 script_bugtraq_id(30425);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1626 security update');
 script_set_attribute(attribute: 'description', value:
'Joan Calvet discovered that httrack, a utility to create local copies of
websites, is vulnerable to a buffer overflow potentially allowing to
execute arbitrary code when passed excessively long URLs.
For the stable distribution (etch), this problem has been fixed in
version 3.40.4-3.1+etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1626');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your httrack package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1626] DSA-1626-1 httrack");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1626-1 httrack");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'httrack', release: '4.0', reference: '3.40.4-3.1+etch1');
deb_check(prefix: 'httrack-doc', release: '4.0', reference: '3.40.4-3.1+etch1');
deb_check(prefix: 'libhttrack-dev', release: '4.0', reference: '3.40.4-3.1+etch1');
deb_check(prefix: 'libhttrack1', release: '4.0', reference: '3.40.4-3.1+etch1');
deb_check(prefix: 'proxytrack', release: '4.0', reference: '3.40.4-3.1+etch1');
deb_check(prefix: 'webhttrack', release: '4.0', reference: '3.40.4-3.1+etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
