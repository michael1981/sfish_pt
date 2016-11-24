# This script was automatically generated from the dsa-533
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15370);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "533");
 script_cve_id("CVE-2004-0591");
 script_bugtraq_id(10588);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-533 security update');
 script_set_attribute(attribute: 'description', value:
'A cross-site scripting vulnerability was discovered in sqwebmail, a
web mail application provided by the courier mail suite, whereby an
attacker could cause web script to be executed within the security
context of the sqwebmail application by injecting it via an email
message.
For the current stable distribution (woody), this problem has been
fixed in version 0.37.3-2.5.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-533');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-533
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA533] DSA-533-1 courier");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-533-1 courier");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'courier-authdaemon', release: '3.0', reference: '0.37.3-2.5');
deb_check(prefix: 'courier-authmysql', release: '3.0', reference: '0.37.3-2.5');
deb_check(prefix: 'courier-base', release: '3.0', reference: '0.37.3-2.5');
deb_check(prefix: 'courier-debug', release: '3.0', reference: '0.37.3-2.5');
deb_check(prefix: 'courier-doc', release: '3.0', reference: '0.37.3-2.5');
deb_check(prefix: 'courier-imap', release: '3.0', reference: '1.4.3-2.5');
deb_check(prefix: 'courier-ldap', release: '3.0', reference: '0.37.3-2.5');
deb_check(prefix: 'courier-maildrop', release: '3.0', reference: '0.37.3-2.5');
deb_check(prefix: 'courier-mlm', release: '3.0', reference: '0.37.3-2.5');
deb_check(prefix: 'courier-mta', release: '3.0', reference: '0.37.3-2.5');
deb_check(prefix: 'courier-pcp', release: '3.0', reference: '0.37.3-2.5');
deb_check(prefix: 'courier-pop', release: '3.0', reference: '0.37.3-2.5');
deb_check(prefix: 'courier-webadmin', release: '3.0', reference: '0.37.3-2.5');
deb_check(prefix: 'sqwebmail', release: '3.0', reference: '0.37.3-2.5');
deb_check(prefix: 'courier', release: '3.0', reference: '0.37.3-2.5');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
