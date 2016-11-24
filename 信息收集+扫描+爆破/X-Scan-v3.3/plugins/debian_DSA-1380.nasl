# This script was automatically generated from the dsa-1380
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(26210);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1380");
 script_cve_id("CVE-2007-5034");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1380 security update');
 script_set_attribute(attribute: 'description', value:
'Kalle Olavi Niemitalo  discovered that elinks, an advanced text-mode WWW 
browser, sent HTTP POST data in cleartext when using an HTTPS proxy server
potentially allowing private information to be disclosed.
For the stable distribution (etch), this problem has been fixed in version
0.11.1-1.2etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1380');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your elinks package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1380] DSA-1380-1 elinks");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1380-1 elinks");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'elinks', release: '4.0', reference: '0.11.1-1.2etch1');
deb_check(prefix: 'elinks-lite', release: '4.0', reference: '0.11.1-1.2etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
