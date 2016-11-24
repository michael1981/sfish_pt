# This script was automatically generated from the dsa-1629
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(33934);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1629");
 script_cve_id("CVE-2008-2936");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1629 security update');
 script_set_attribute(attribute: 'description', value:
'Sebastian Krahmer discovered that Postfix, a mail transfer agent,
incorrectly checks the ownership of a mailbox. In some configurations,
this allows for appending data to arbitrary files as root.
Note that only specific configurations are vulnerable; the default
Debian installation is not affected. Only a configuration meeting
the following requirements is vulnerable:
For a detailed treating of the issue, please refer to the upstream
author\'s announcement.
For the stable distribution (etch), this problem has been fixed in
version 2.3.8-2+etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1629');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your postfix package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1629] DSA-1629-2 postfix");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1629-2 postfix");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'postfix', release: '4.0', reference: '2.3.8-2+etch1');
deb_check(prefix: 'postfix-cdb', release: '4.0', reference: '2.3.8-2+etch1');
deb_check(prefix: 'postfix-dev', release: '4.0', reference: '2.3.8-2+etch1');
deb_check(prefix: 'postfix-doc', release: '4.0', reference: '2.3.8-2+etch1');
deb_check(prefix: 'postfix-ldap', release: '4.0', reference: '2.3.8-2+etch1');
deb_check(prefix: 'postfix-mysql', release: '4.0', reference: '2.3.8-2+etch1');
deb_check(prefix: 'postfix-pcre', release: '4.0', reference: '2.3.8-2+etch1');
deb_check(prefix: 'postfix-pgsql', release: '4.0', reference: '2.3.8-2+etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
