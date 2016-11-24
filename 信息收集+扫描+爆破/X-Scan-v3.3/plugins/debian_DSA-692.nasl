# This script was automatically generated from the dsa-692
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(17299);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "692");
 script_cve_id("CVE-2005-0205");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-692 security update');
 script_set_attribute(attribute: 'description', value:
'The KDE team fixed a bug in kppp in 2002 which was now discovered to be
exploitable by iDEFENSE.  By opening a sufficiently large number of
file descriptors before executing kppp which is installed setuid root a
local attacker is able to take over privileged file descriptors.
For the stable distribution (woody) this problem has been fixed in
version 2.2.2-14.7.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-692');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your kppp package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA692] DSA-692-1 kdenetwork");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-692-1 kdenetwork");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'kdict', release: '3.0', reference: '2.2.2-14.7');
deb_check(prefix: 'kit', release: '3.0', reference: '2.2.2-14.7');
deb_check(prefix: 'klisa', release: '3.0', reference: '2.2.2-14.7');
deb_check(prefix: 'kmail', release: '3.0', reference: '2.2.2-14.7');
deb_check(prefix: 'knewsticker', release: '3.0', reference: '2.2.2-14.7');
deb_check(prefix: 'knode', release: '3.0', reference: '2.2.2-14.7');
deb_check(prefix: 'korn', release: '3.0', reference: '2.2.2-14.7');
deb_check(prefix: 'kppp', release: '3.0', reference: '2.2.2-14.7');
deb_check(prefix: 'ksirc', release: '3.0', reference: '2.2.2-14.7');
deb_check(prefix: 'ktalkd', release: '3.0', reference: '2.2.2-14.7');
deb_check(prefix: 'libkdenetwork1', release: '3.0', reference: '2.2.2-14.7');
deb_check(prefix: 'libmimelib-dev', release: '3.0', reference: '2.2.2-14.7');
deb_check(prefix: 'libmimelib1', release: '3.0', reference: '2.2.2-14.7');
deb_check(prefix: 'kdenetwork', release: '3.0', reference: '2.2.2-14.7');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
