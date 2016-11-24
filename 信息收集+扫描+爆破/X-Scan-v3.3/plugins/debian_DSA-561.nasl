# This script was automatically generated from the dsa-561
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15659);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "561");
 script_cve_id("CVE-2004-0687", "CVE-2004-0688");
 script_xref(name: "CERT", value: "537878");
 script_xref(name: "CERT", value: "882750");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-561 security update');
 script_set_attribute(attribute: 'description', value:
'Chris Evans discovered several stack and integer overflows in the
libXpm library which is provided by X.Org, XFree86 and LessTif.
For the stable distribution (woody) this problem has been fixed in
version 4.1.0-16woody4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-561');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libxpm packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA561] DSA-561-1 xfree86");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-561-1 xfree86");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'lbxproxy', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'libdps-dev', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'libdps1', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'libdps1-dbg', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'libxaw6', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'libxaw6-dbg', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'libxaw6-dev', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'libxaw7', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'libxaw7-dbg', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'libxaw7-dev', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'proxymngr', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'twm', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'x-window-system', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'x-window-system-core', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'xbase-clients', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'xdm', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'xfonts-100dpi', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'xfonts-100dpi-transcoded', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'xfonts-75dpi', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'xfonts-75dpi-transcoded', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'xfonts-base', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'xfonts-base-transcoded', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'xfonts-cyrillic', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'xfonts-pex', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'xfonts-scalable', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'xfree86-common', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'xfs', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'xfwp', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'xlib6g', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'xlib6g-dev', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'xlibmesa-dev', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'xlibmesa3', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'xlibmesa3-dbg', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'xlibosmesa-dev', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'xlibosmesa3', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'xlibosmesa3-dbg', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'xlibs', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'xlibs-dbg', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'xlibs-dev', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'xlibs-pic', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'xmh', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'xnest', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'xprt', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'xserver-common', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'xserver-xfree86', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'xspecs', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'xterm', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'xutils', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'xvfb', release: '3.0', reference: '4.1.0-16woody4');
deb_check(prefix: 'xfree86', release: '3.0', reference: '4.1.0-16woody4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
