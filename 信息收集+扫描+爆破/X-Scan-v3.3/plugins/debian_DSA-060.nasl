# This script was automatically generated from the dsa-060
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14897);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "060");
 script_cve_id("CVE-2001-0819");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-060 security update');
 script_set_attribute(attribute: 'description', value:
'Wolfram Kleff found a problem in fetchmail: it would crash when
processing emails with extremely long headers. The problem was
a buffer overflow in the header parser which could be exploited.

This has been fixed in version 5.3.3-1.2, and we recommend that
you upgrade your fetchmail package immediately.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-060');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-060
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA060] DSA-060-1 fetchmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-060-1 fetchmail");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'fetchmail', release: '2.2', reference: '5.3.3-1.2');
deb_check(prefix: 'fetchmailconf', release: '2.2', reference: '5.3.3-1.2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
