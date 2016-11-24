# This script was automatically generated from the dsa-900
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22766);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "900");
 script_cve_id("CVE-2005-3088");
 script_bugtraq_id(15179);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-900 security update');
 script_set_attribute(attribute: 'description', value:
'Due to restrictive dependency definition for fetchmail-ssl the updated fetchmailconf
package couldn\'t be installed on the old stable distribution (woody)
together with fetchmail-ssl.  Hence, this update loosens it, so that
the update can be pulled in.  For completeness we\'re including the
original advisory text:
Thomas Wolff discovered that the fetchmailconf program which is
provided as part of fetchmail, an SSL enabled POP3, APOP, IMAP mail
gatherer/forwarder, creates the new configuration in an insecure
fashion that can lead to leaking passwords for mail accounts to local
users.
This update also fixes a regression in the package for stable caused
by the last security update.
For the old stable distribution (woody) this problem has been fixed in
version 5.9.11-6.4 of fetchmail and in version 5.9.11-6.3 of
fetchmail-ssl.
For the stable distribution (sarge) this problem has been fixed in
version 6.2.5-12sarge3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-900');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your fetchmail package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA900] DSA-900-3 fetchmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-900-3 fetchmail");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'fetchmail', release: '3.0', reference: '5.9.11-6.4');
deb_check(prefix: 'fetchmail-common', release: '3.0', reference: '5.9.11-6.4');
deb_check(prefix: 'fetchmail-ssl', release: '3.0', reference: '5.9.11-6.3');
deb_check(prefix: 'fetchmailconf', release: '3.0', reference: '5.9.11-6.4');
deb_check(prefix: 'fetchmail', release: '3.1', reference: '6.2.5-12sarge3');
deb_check(prefix: 'fetchmail-ssl', release: '3.1', reference: '6.2.5-12sarge3');
deb_check(prefix: 'fetchmailconf', release: '3.1', reference: '6.2.5-12sarge3');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
