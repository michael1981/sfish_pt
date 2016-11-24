# This script was automatically generated from the dsa-291
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15128);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "291");
 script_cve_id("CVE-2003-0323");
 script_bugtraq_id(7093, 7094, 7095, 7098);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-291 security update');
 script_set_attribute(attribute: 'description', value:
'Timo Sirainen discovered several problems in ircII, a popular
client for Internet Relay Chat (IRC).  A malicious server could
craft special reply strings, triggering the client to write beyond
buffer boundaries.  This could lead to a denial of service if the
client only crashes, but may also lead to executing of arbitrary code
under the user id of the chatting user.
For the stable distribution (woody) these problems have been fixed in
version 20020322-1.1.
For the old stable distribution (potato) these problems have been
fixed in version 4.4M-1.1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-291');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your ircII package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA291] DSA-291-1 ircii");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-291-1 ircii");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ircii', release: '2.2', reference: '4.4M-1.1');
deb_check(prefix: 'ircii', release: '3.0', reference: '20020322-1.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
