# This script was automatically generated from the dsa-208
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15045);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "208");
 script_cve_id("CVE-2002-1323");
 script_bugtraq_id(6111);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-208 security update');
 script_set_attribute(attribute: 'description', value:
'A security hole has been discovered in Safe.pm which is used in all
versions of Perl.  The Safe extension module allows the creation of
compartments in which perl code can be evaluated in a new namespace
and the code evaluated in the compartment cannot refer to variables
outside this namespace.  However, when a Safe compartment has already
been used, there\'s no guarantee that it is Safe any longer, because
there\'s a way for code to be executed within the Safe compartment to
alter its operation mask.  Thus, programs that use a Safe compartment
only once aren\'t affected by this bug.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-208');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your Perl packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA208] DSA-208-1 perl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-208-1 perl");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'perl-5.004', release: '2.2', reference: '5.004.05-6.2');
deb_check(prefix: 'perl-5.004-base', release: '2.2', reference: '5.004.05-6.2');
deb_check(prefix: 'perl-5.004-debug', release: '2.2', reference: '5.004.05-6.2');
deb_check(prefix: 'perl-5.004-doc', release: '2.2', reference: '5.004.05-6.2');
deb_check(prefix: 'perl-5.004-suid', release: '2.2', reference: '5.004.05-6.2');
deb_check(prefix: 'perl-5.005', release: '2.2', reference: '5.005.03-7.2');
deb_check(prefix: 'perl-5.005-base', release: '2.2', reference: '5.005.03-7.2');
deb_check(prefix: 'perl-5.005-debug', release: '2.2', reference: '5.005.03-7.2');
deb_check(prefix: 'perl-5.005-doc', release: '2.2', reference: '5.005.03-7.2');
deb_check(prefix: 'perl-5.005-suid', release: '2.2', reference: '5.005.03-7.2');
deb_check(prefix: 'perl-5.005-thread', release: '2.2', reference: '5.005.03-7.2');
deb_check(prefix: 'libcgi-fast-perl', release: '3.0', reference: '5.6.1-8.2');
deb_check(prefix: 'libperl-dev', release: '3.0', reference: '5.6.1-8.2');
deb_check(prefix: 'libperl5.6', release: '3.0', reference: '5.6.1-8.2');
deb_check(prefix: 'perl', release: '3.0', reference: '5.6.1-8.2');
deb_check(prefix: 'perl-base', release: '3.0', reference: '5.6.1-8.2');
deb_check(prefix: 'perl-debug', release: '3.0', reference: '5.6.1-8.2');
deb_check(prefix: 'perl-doc', release: '3.0', reference: '5.6.1-8.2');
deb_check(prefix: 'perl-modules', release: '3.0', reference: '5.6.1-8.2');
deb_check(prefix: 'perl-suid', release: '3.0', reference: '5.6.1-8.2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
