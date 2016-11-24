# This script was automatically generated from the dsa-690
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(17232);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "690");
 script_cve_id("CVE-2005-0107");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-690 security update');
 script_set_attribute(attribute: 'description', value:
'Bastian Blank discovered a vulnerability in bsmtpd, a batched SMTP mailer for
sendmail and postfix.  Unsanitised addresses can cause the execution
of arbitrary commands during alleged mail delivery.
For the stable distribution (woody) this problem has been fixed in
version 2.3pl8b-12woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-690');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your bsmtpd package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA690] DSA-690-1 bsmtpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-690-1 bsmtpd");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'bsmtpd', release: '3.0', reference: '2.3pl8b-12woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
