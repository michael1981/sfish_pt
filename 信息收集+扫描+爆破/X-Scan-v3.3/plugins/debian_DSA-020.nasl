# This script was automatically generated from the dsa-020
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14857);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "020");
 script_cve_id("CVE-2001-0108", "CVE-2001-1385");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-020 security update');
 script_set_attribute(attribute: 'description', value:
'The Zend people have found a vulnerability in older
versions of PHP4 (the original advisory speaks of 4.0.4 while the bugs are
present in 4.0.3 as well). It is possible to specify PHP directives on a
per-directory basis which leads to a remote attacker crafting an HTTP request
that would cause the next page to be served with the wrong values for these
directives. Also even if PHP is installed, it can be activated and deactivated
on a per-directory or per-virtual host basis using the "engine=on" or
"engine=off" directive. This setting can be leaked to other virtual hosts on
the same machine, effectively disabling PHP for those hosts and resulting in
PHP source code being sent to the client instead of being executed on the
server.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-020');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-020
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA020] DSA-020-1 php4");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-020-1 php4");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'php4', release: '2.2', reference: '4.0.3pl1-0potato1.1');
deb_check(prefix: 'php4-cgi', release: '2.2', reference: '4.0.3pl1-0potato1.1');
deb_check(prefix: 'php4-cgi-gd', release: '2.2', reference: '4.0.3pl1-0potato1.1');
deb_check(prefix: 'php4-cgi-imap', release: '2.2', reference: '4.0.3pl1-0potato1.1');
deb_check(prefix: 'php4-cgi-ldap', release: '2.2', reference: '4.0.3pl1-0potato1.1');
deb_check(prefix: 'php4-cgi-mhash', release: '2.2', reference: '4.0.3pl1-0potato1.1');
deb_check(prefix: 'php4-cgi-mysql', release: '2.2', reference: '4.0.3pl1-0potato1.1');
deb_check(prefix: 'php4-cgi-pgsql', release: '2.2', reference: '4.0.3pl1-0potato1.1');
deb_check(prefix: 'php4-cgi-snmp', release: '2.2', reference: '4.0.3pl1-0potato1.1');
deb_check(prefix: 'php4-cgi-xml', release: '2.2', reference: '4.0.3pl1-0potato1.1');
deb_check(prefix: 'php4-gd', release: '2.2', reference: '4.0.3pl1-0potato1.1');
deb_check(prefix: 'php4-imap', release: '2.2', reference: '4.0.3pl1-0potato1.1');
deb_check(prefix: 'php4-ldap', release: '2.2', reference: '4.0.3pl1-0potato1.1');
deb_check(prefix: 'php4-mhash', release: '2.2', reference: '4.0.3pl1-0potato1.1');
deb_check(prefix: 'php4-mysql', release: '2.2', reference: '4.0.3pl1-0potato1.1');
deb_check(prefix: 'php4-pgsql', release: '2.2', reference: '4.0.3pl1-0potato1.1');
deb_check(prefix: 'php4-snmp', release: '2.2', reference: '4.0.3pl1-0potato1.1');
deb_check(prefix: 'php4-xml', release: '2.2', reference: '4.0.3pl1-0potato1.1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
