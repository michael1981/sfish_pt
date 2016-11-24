# This script was automatically generated from the dsa-818
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19787);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "818");
 script_cve_id("CVE-2005-2101");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-818 security update');
 script_set_attribute(attribute: 'description', value:
'Javier Fernández-Sanguino Peña discovered that langen2kvhtml from the
kvoctrain package from the kdeedu suite creates temporary files in an
insecure fashion.  This leaves them open for symlink attacks.
The old stable distribution (woody) is not affected by these problems.
For the stable distribution (sarge) these problems have been fixed in
version 3.3.2-3.sarge.1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-818');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your kvoctrain package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA818] DSA-818-1 kdeedu");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-818-1 kdeedu");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'kalzium', release: '3.1', reference: '3.3.2-3.sarge.1');
deb_check(prefix: 'kbruch', release: '3.1', reference: '3.3.2-3.sarge.1');
deb_check(prefix: 'kdeedu', release: '3.1', reference: '3.3.2-3.sarge.1');
deb_check(prefix: 'kdeedu-data', release: '3.1', reference: '3.3.2-3.sarge.1');
deb_check(prefix: 'kdeedu-doc-html', release: '3.1', reference: '3.3.2-3.sarge.1');
deb_check(prefix: 'keduca', release: '3.1', reference: '3.3.2-3.sarge.1');
deb_check(prefix: 'khangman', release: '3.1', reference: '3.3.2-3.sarge.1');
deb_check(prefix: 'kig', release: '3.1', reference: '3.3.2-3.sarge.1');
deb_check(prefix: 'kiten', release: '3.1', reference: '3.3.2-3.sarge.1');
deb_check(prefix: 'klatin', release: '3.1', reference: '3.3.2-3.sarge.1');
deb_check(prefix: 'klettres', release: '3.1', reference: '3.3.2-3.sarge.1');
deb_check(prefix: 'klettres-data', release: '3.1', reference: '3.3.2-3.sarge.1');
deb_check(prefix: 'kmessedwords', release: '3.1', reference: '3.3.2-3.sarge.1');
deb_check(prefix: 'kmplot', release: '3.1', reference: '3.3.2-3.sarge.1');
deb_check(prefix: 'kpercentage', release: '3.1', reference: '3.3.2-3.sarge.1');
deb_check(prefix: 'kstars', release: '3.1', reference: '3.3.2-3.sarge.1');
deb_check(prefix: 'kstars-data', release: '3.1', reference: '3.3.2-3.sarge.1');
deb_check(prefix: 'ktouch', release: '3.1', reference: '3.3.2-3.sarge.1');
deb_check(prefix: 'kturtle', release: '3.1', reference: '3.3.2-3.sarge.1');
deb_check(prefix: 'kverbos', release: '3.1', reference: '3.3.2-3.sarge.1');
deb_check(prefix: 'kvoctrain', release: '3.1', reference: '3.3.2-3.sarge.1');
deb_check(prefix: 'kwordquiz', release: '3.1', reference: '3.3.2-3.sarge.1');
deb_check(prefix: 'libkdeedu-dev', release: '3.1', reference: '3.3.2-3.sarge.1');
deb_check(prefix: 'libkdeedu1', release: '3.1', reference: '3.3.2-3.sarge.1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
