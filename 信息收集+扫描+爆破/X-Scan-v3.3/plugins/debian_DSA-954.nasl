# This script was automatically generated from the dsa-954
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22820);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "954");
 script_cve_id("CVE-2006-0106");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-954 security update');
 script_set_attribute(attribute: 'description', value:
'H D Moore has discovered that Wine, a free implementation of the Microsoft
Windows APIs, inherits a design flaw from the Windows GDI API, which may
lead to the execution of code through GDI escape functions in WMF files.
The old stable distribution (woody) does not seem to be affected by this
problem.
For the stable distribution (sarge) this problem has been fixed in
version 0.0.20050310-1.2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-954');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your wine packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA954] DSA-954-1 wine");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-954-1 wine");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libwine', release: '3.1', reference: '0.0.20050310-1.2');
deb_check(prefix: 'libwine-alsa', release: '3.1', reference: '0.0.20050310-1.2');
deb_check(prefix: 'libwine-arts', release: '3.1', reference: '0.0.20050310-1.2');
deb_check(prefix: 'libwine-capi', release: '3.1', reference: '0.0.20050310-1.2');
deb_check(prefix: 'libwine-dev', release: '3.1', reference: '0.0.20050310-1.2');
deb_check(prefix: 'libwine-jack', release: '3.1', reference: '0.0.20050310-1.2');
deb_check(prefix: 'libwine-nas', release: '3.1', reference: '0.0.20050310-1.2');
deb_check(prefix: 'libwine-print', release: '3.1', reference: '0.0.20050310-1.2');
deb_check(prefix: 'libwine-twain', release: '3.1', reference: '0.0.20050310-1.2');
deb_check(prefix: 'wine', release: '3.1', reference: '0.0.20050310-1.2');
deb_check(prefix: 'wine-doc', release: '3.1', reference: '0.0.20050310-1.2');
deb_check(prefix: 'wine-utils', release: '3.1', reference: '0.0.20050310-1.2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
