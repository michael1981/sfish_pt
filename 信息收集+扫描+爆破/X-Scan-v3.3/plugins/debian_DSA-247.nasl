# This script was automatically generated from the dsa-247
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15084);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "247");
 script_cve_id("CVE-2003-0040");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-247 security update');
 script_set_attribute(attribute: 'description', value:
'The developers of courier, an integrated user side mail server,
discovered a problem in the PostgreSQL auth module.  Not all
potentially malicious characters were sanitized before the username
was passed to the PostgreSQL engine.  An attacker could inject
arbitrary SQL commands and queries exploiting this vulnerability.  The
MySQL auth module is not affected.
For the stable distribution (woody) this problem has been fixed in
version 0.37.3-3.3.
The old stable distribution (potato) does not contain courier packages.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-247');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your courier-authpostgresql package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA247] DSA-247-1 courier-ssl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-247-1 courier-ssl");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'courier-authpostgresql', release: '3.0', reference: '0.37.3-3.3');
deb_check(prefix: 'courier-imap-ssl', release: '3.0', reference: '1.4.3-3.3');
deb_check(prefix: 'courier-mta-ssl', release: '3.0', reference: '0.37.3-3.3');
deb_check(prefix: 'courier-pop-ssl', release: '3.0', reference: '0.37.3-3.3');
deb_check(prefix: 'courier-ssl', release: '3.0', reference: '0.37.3-3.3');
deb_check(prefix: 'courier', release: '3.0', reference: '0.37.3-3.3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
