# This script was automatically generated from the dsa-274
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15111);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "274");
 script_cve_id("CVE-2003-0167");
 script_bugtraq_id(7229);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-274 security update');
 script_set_attribute(attribute: 'description', value:
'Byrial Jensen discovered a couple of off-by-one buffer overflow in the
IMAP code of Mutt, a text-oriented mail reader supporting IMAP, MIME,
GPG, PGP and threading.  This problem could potentially allow a remote
malicious IMAP server to cause a denial of service (crash) and
possibly execute arbitrary code via a specially crafted mail folder.
For the stable distribution (woody) this problem has been fixed in
version 1.3.28-2.2.
The old stable distribution (potato) is also affected by this problem
and an update will follow.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-274');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mutt package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA274] DSA-274-1 mutt");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-274-1 mutt");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'mutt', release: '2.2', reference: '1.2.5-5.2');
deb_check(prefix: 'mutt', release: '3.0', reference: '1.3.28-2.2');
deb_check(prefix: 'mutt-utf8', release: '3.0', reference: '1.3.28-2.2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
