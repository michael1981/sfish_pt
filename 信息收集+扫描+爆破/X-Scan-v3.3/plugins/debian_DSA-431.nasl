# This script was automatically generated from the dsa-431
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15268);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "431");
 script_cve_id("CVE-2003-0618");
 script_bugtraq_id(9543);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-431 security update');
 script_set_attribute(attribute: 'description', value:
'Paul Szabo discovered a number of similar bugs in suidperl, a helper
program to run perl scripts with setuid privileges.  By exploiting
these bugs, an attacker could abuse suidperl to discover information
about files (such as testing for their existence and some of their
permissions) that should not be accessible to unprivileged users.
For the current stable distribution (woody) this problem has been
fixed in version 5.6.1-8.6.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-431');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-431
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA431] DSA-431-1 perl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-431-1 perl");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libcgi-fast-perl', release: '3.0', reference: '5.6.1-8.6');
deb_check(prefix: 'libperl-dev', release: '3.0', reference: '5.6.1-8.6');
deb_check(prefix: 'libperl5.6', release: '3.0', reference: '5.6.1-8.6');
deb_check(prefix: 'perl', release: '3.0', reference: '5.6.1-8.6');
deb_check(prefix: 'perl-base', release: '3.0', reference: '5.6.1-8.6');
deb_check(prefix: 'perl-debug', release: '3.0', reference: '5.6.1-8.6');
deb_check(prefix: 'perl-doc', release: '3.0', reference: '5.6.1-8.6');
deb_check(prefix: 'perl-modules', release: '3.0', reference: '5.6.1-8.6');
deb_check(prefix: 'perl-suid', release: '3.0', reference: '5.6.1-8.6');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
