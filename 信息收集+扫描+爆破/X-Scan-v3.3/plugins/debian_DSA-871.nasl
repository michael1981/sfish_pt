# This script was automatically generated from the dsa-871
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22737);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "871");
 script_cve_id("CVE-2005-2958");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-871 security update');
 script_set_attribute(attribute: 'description', value:
'Steve Kemp discovered two format string vulnerabilities in libgda2,
the GNOME Data Access library for GNOME2, which may lead to the
execution of arbitrary code in programs that use this library.
The old stable distribution (woody) is not affected by these problems.
For the stable distribution (sarge) these problems have been fixed in
version 1.2.1-2sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-871');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libgda2 packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA871] DSA-871-2 libgda2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-871-2 libgda2");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gda2-freetds', release: '3.1', reference: '1.2.1-2sarge1');
deb_check(prefix: 'gda2-mysql', release: '3.1', reference: '1.2.1-2sarge1');
deb_check(prefix: 'gda2-odbc', release: '3.1', reference: '1.2.1-2sarge1');
deb_check(prefix: 'gda2-postgres', release: '3.1', reference: '1.2.1-2sarge1');
deb_check(prefix: 'gda2-sqlite', release: '3.1', reference: '1.2.1-2sarge1');
deb_check(prefix: 'libgda2-3', release: '3.1', reference: '1.2.1-2sarge1');
deb_check(prefix: 'libgda2-3-dbg', release: '3.1', reference: '1.2.1-2sarge1');
deb_check(prefix: 'libgda2-common', release: '3.1', reference: '1.2.1-2sarge1');
deb_check(prefix: 'libgda2-dev', release: '3.1', reference: '1.2.1-2sarge1');
deb_check(prefix: 'libgda2-doc', release: '3.1', reference: '1.2.1-2sarge1');
deb_check(prefix: 'libgda2', release: '3.1', reference: '1.2.1-2sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
