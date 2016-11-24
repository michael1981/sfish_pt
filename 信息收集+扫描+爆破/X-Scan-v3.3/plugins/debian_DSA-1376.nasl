# This script was automatically generated from the dsa-1376
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(26079);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1376");
 script_cve_id("CVE-2007-4569");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1376 security update');
 script_set_attribute(attribute: 'description', value:
'iKees Huijgen discovered that under certain circumstances KDM, an X
session manager for KDE, could be tricked into
allowing user logins without a password.
For the old stable distribution (sarge), this problem was not present.
For the stable distribution (etch), this problem has been fixed in version
4:3.5.5a.dfsg.1-6etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1376');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your kdebase package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1376] DSA-1376-1 kdebase");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1376-1 kdebase");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'kappfinder', release: '4.0', reference: '3.5.5a.dfsg.1-6etch1');
deb_check(prefix: 'kate', release: '4.0', reference: '3.5.5a.dfsg.1-6etch1');
deb_check(prefix: 'kcontrol', release: '4.0', reference: '3.5.5a.dfsg.1-6etch1');
deb_check(prefix: 'kdebase', release: '4.0', reference: '3.5.5a.dfsg.1-6etch1');
deb_check(prefix: 'kdebase-bin', release: '4.0', reference: '3.5.5a.dfsg.1-6etch1');
deb_check(prefix: 'kdebase-data', release: '4.0', reference: '3.5.5a.dfsg.1-6etch1');
deb_check(prefix: 'kdebase-dbg', release: '4.0', reference: '3.5.5a.dfsg.1-6etch1');
deb_check(prefix: 'kdebase-dev', release: '4.0', reference: '3.5.5a.dfsg.1-6etch1');
deb_check(prefix: 'kdebase-doc', release: '4.0', reference: '3.5.5a.dfsg.1-6etch1');
deb_check(prefix: 'kdebase-doc-html', release: '4.0', reference: '3.5.5a.dfsg.1-6etch1');
deb_check(prefix: 'kdebase-kio-plugins', release: '4.0', reference: '3.5.5a.dfsg.1-6etch1');
deb_check(prefix: 'kdepasswd', release: '4.0', reference: '3.5.5a.dfsg.1-6etch1');
deb_check(prefix: 'kdeprint', release: '4.0', reference: '3.5.5a.dfsg.1-6etch1');
deb_check(prefix: 'kdesktop', release: '4.0', reference: '3.5.5a.dfsg.1-6etch1');
deb_check(prefix: 'kdm', release: '4.0', reference: '3.5.5a.dfsg.1-6etch1');
deb_check(prefix: 'kfind', release: '4.0', reference: '3.5.5a.dfsg.1-6etch1');
deb_check(prefix: 'khelpcenter', release: '4.0', reference: '3.5.5a.dfsg.1-6etch1');
deb_check(prefix: 'kicker', release: '4.0', reference: '3.5.5a.dfsg.1-6etch1');
deb_check(prefix: 'klipper', release: '4.0', reference: '3.5.5a.dfsg.1-6etch1');
deb_check(prefix: 'kmenuedit', release: '4.0', reference: '3.5.5a.dfsg.1-6etch1');
deb_check(prefix: 'konqueror', release: '4.0', reference: '3.5.5a.dfsg.1-6etch1');
deb_check(prefix: 'konqueror-nsplugins', release: '4.0', reference: '3.5.5a.dfsg.1-6etch1');
deb_check(prefix: 'konsole', release: '4.0', reference: '3.5.5a.dfsg.1-6etch1');
deb_check(prefix: 'kpager', release: '4.0', reference: '3.5.5a.dfsg.1-6etch1');
deb_check(prefix: 'kpersonalizer', release: '4.0', reference: '3.5.5a.dfsg.1-6etch1');
deb_check(prefix: 'ksmserver', release: '4.0', reference: '3.5.5a.dfsg.1-6etch1');
deb_check(prefix: 'ksplash', release: '4.0', reference: '3.5.5a.dfsg.1-6etch1');
deb_check(prefix: 'ksysguard', release: '4.0', reference: '3.5.5a.dfsg.1-6etch1');
deb_check(prefix: 'ksysguardd', release: '4.0', reference: '3.5.5a.dfsg.1-6etch1');
deb_check(prefix: 'ktip', release: '4.0', reference: '3.5.5a.dfsg.1-6etch1');
deb_check(prefix: 'kwin', release: '4.0', reference: '3.5.5a.dfsg.1-6etch1');
deb_check(prefix: 'libkonq4', release: '4.0', reference: '3.5.5a.dfsg.1-6etch1');
deb_check(prefix: 'libkonq4-dev', release: '4.0', reference: '3.5.5a.dfsg.1-6etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
