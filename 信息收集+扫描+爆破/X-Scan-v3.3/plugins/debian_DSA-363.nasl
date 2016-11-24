# This script was automatically generated from the dsa-363
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15200);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "363");
 script_cve_id("CVE-2003-0468", "CVE-2003-0540");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-363 security update');
 script_set_attribute(attribute: 'description', value:
'The postfix mail transport agent in Debian 3.0 contains two
vulnerabilities:
For the current stable distribution (woody) these problems have been
fixed in version 1.1.11-0.woody3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-363');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-363
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA363] DSA-363-1 postfix");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-363-1 postfix");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'postfix', release: '3.0', reference: '1.1.11-0.woody3');
deb_check(prefix: 'postfix-dev', release: '3.0', reference: '1.1.11-0.woody3');
deb_check(prefix: 'postfix-doc', release: '3.0', reference: '1.1.11-0.woody3');
deb_check(prefix: 'postfix-ldap', release: '3.0', reference: '1.1.11-0.woody3');
deb_check(prefix: 'postfix-mysql', release: '3.0', reference: '1.1.11-0.woody3');
deb_check(prefix: 'postfix-pcre', release: '3.0', reference: '1.1.11-0.woody3');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
