# This script was automatically generated from the dsa-1359
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25959);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1359");
 script_cve_id("CVE-2007-2231");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1359 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that dovecot, a secure mail server that supports mbox
and maildir mailboxes, when configured to use non-system-user spools
and compressed folders, may allow directory traversal in mailbox names.
For the old stable distribution (sarge), this problem was not present.
For the stable distribution (etch), this problem has been fixed in
version 1.0.rc15-2etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1359');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your dovecot package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1359] DSA-1359-1 dovecot");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1359-1 dovecot");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'dovecot-common', release: '4.0', reference: '1.0.rc15-2etch1');
deb_check(prefix: 'dovecot-imapd', release: '4.0', reference: '1.0.rc15-2etch1');
deb_check(prefix: 'dovecot-pop3d', release: '4.0', reference: '1.0.rc15-2etch1');
deb_check(prefix: 'dovecot', release: '4.0', reference: '1.0.rc15-2etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
