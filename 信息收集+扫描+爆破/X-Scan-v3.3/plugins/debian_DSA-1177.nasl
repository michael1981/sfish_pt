# This script was automatically generated from the dsa-1177
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22719);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1177");
 script_cve_id("CVE-2006-4246");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1177 security update');
 script_set_attribute(attribute: 'description', value:
'Hendrik Weimer discovered that it is possible for a normal user to
disable the login shell of the root account via usermin, a web-based
administration tool.
For the stable distribution (sarge) this problem has been fixed in
version 1.110-3.1.
In the upstream distribution this problem is fixed in version 1.220.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1177');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your usermin package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1177] DSA-1177-1 usermin");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1177-1 usermin");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'usermin', release: '3.1', reference: '1.110-3.1');
deb_check(prefix: 'usermin-at', release: '3.1', reference: '1.110-3.1');
deb_check(prefix: 'usermin-changepass', release: '3.1', reference: '1.110-3.1');
deb_check(prefix: 'usermin-chfn', release: '3.1', reference: '1.110-3.1');
deb_check(prefix: 'usermin-commands', release: '3.1', reference: '1.110-3.1');
deb_check(prefix: 'usermin-cron', release: '3.1', reference: '1.110-3.1');
deb_check(prefix: 'usermin-cshrc', release: '3.1', reference: '1.110-3.1');
deb_check(prefix: 'usermin-fetchmail', release: '3.1', reference: '1.110-3.1');
deb_check(prefix: 'usermin-forward', release: '3.1', reference: '1.110-3.1');
deb_check(prefix: 'usermin-gnupg', release: '3.1', reference: '1.110-3.1');
deb_check(prefix: 'usermin-htaccess', release: '3.1', reference: '1.110-3.1');
deb_check(prefix: 'usermin-htpasswd', release: '3.1', reference: '1.110-3.1');
deb_check(prefix: 'usermin-mailbox', release: '3.1', reference: '1.110-3.1');
deb_check(prefix: 'usermin-man', release: '3.1', reference: '1.110-3.1');
deb_check(prefix: 'usermin-mysql', release: '3.1', reference: '1.110-3.1');
deb_check(prefix: 'usermin-plan', release: '3.1', reference: '1.110-3.1');
deb_check(prefix: 'usermin-postgresql', release: '3.1', reference: '1.110-3.1');
deb_check(prefix: 'usermin-proc', release: '3.1', reference: '1.110-3.1');
deb_check(prefix: 'usermin-procmail', release: '3.1', reference: '1.110-3.1');
deb_check(prefix: 'usermin-quota', release: '3.1', reference: '1.110-3.1');
deb_check(prefix: 'usermin-schedule', release: '3.1', reference: '1.110-3.1');
deb_check(prefix: 'usermin-shell', release: '3.1', reference: '1.110-3.1');
deb_check(prefix: 'usermin-spamassassin', release: '3.1', reference: '1.110-3.1');
deb_check(prefix: 'usermin-ssh', release: '3.1', reference: '1.110-3.1');
deb_check(prefix: 'usermin-tunnel', release: '3.1', reference: '1.110-3.1');
deb_check(prefix: 'usermin-updown', release: '3.1', reference: '1.110-3.1');
deb_check(prefix: 'usermin-usermount', release: '3.1', reference: '1.110-3.1');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
