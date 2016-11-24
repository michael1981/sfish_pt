# This script was automatically generated from the dsa-386
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15223);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "386");
 script_cve_id("CVE-2002-1271");
 script_bugtraq_id(6104);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-386 security update');
 script_set_attribute(attribute: 'description', value:
'The SuSE security team discovered during an audit a bug in
Mail::Mailer, a Perl module used for sending email, whereby
potentially untrusted input is passed to a program such as mailx,
which may interpret certain escape sequences as commands to be
executed.
This bug has been fixed by removing support for programs such as mailx
as a transport for sending mail.  Instead, alternative mechanisms are
used.
For the stable distribution (woody) this problem has been fixed in
version 1.44-1woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-386');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-386
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA386] DSA-386-1 libmailtools-perl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-386-1 libmailtools-perl");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libmailtools-perl', release: '3.0', reference: '1.44-1woody2');
deb_check(prefix: 'mailtools', release: '3.0', reference: '1.44-1woody2');
deb_check(prefix: 'libmailtools-perl', release: '3.0', reference: '1.44-1woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
