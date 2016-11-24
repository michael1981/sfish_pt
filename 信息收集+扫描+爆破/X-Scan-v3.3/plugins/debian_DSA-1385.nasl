# This script was automatically generated from the dsa-1385
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(26976);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1385");
 script_cve_id("CVE-2007-4568");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1385 security update');
 script_set_attribute(attribute: 'description', value:
'Sean Larsson discovered that two code paths inside the X Font Server
handle integer values insecurely, which may lead to the execution of
arbitrary code.
For the oldstable distribution (sarge) this problem has been fixed in
version 4.3.0.dfsg.1-14sarge5 of xfree86. Packages for m68k are not
yet available. They will be provided later.
For the stable distribution (etch) this problem has been fixed in
version 1.0.1-7.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1385');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your xfs packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1385] DSA-1385-1 xfs");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1385-1 xfs");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'lbxproxy', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libdps-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libdps1', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libdps1-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libice-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libice6', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libice6-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libsm-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libsm6', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libsm6-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libx11-6', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libx11-6-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libx11-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxaw6', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxaw6-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxaw6-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxaw7', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxaw7-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxaw7-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxext-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxext6', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxext6-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxft1', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxft1-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxi-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxi6', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxi6-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxmu-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxmu6', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxmu6-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxmuu-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxmuu1', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxmuu1-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxp-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxp6', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxp6-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxpm-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxpm4', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxpm4-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxrandr-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxrandr2', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxrandr2-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxt-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxt6', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxt6-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxtrap-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxtrap6', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxtrap6-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxtst-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxtst6', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxtst6-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxv-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxv1', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'libxv1-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'pm-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'proxymngr', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'twm', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'x-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'x-window-system', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'x-window-system-core', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'x-window-system-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xbase-clients', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xdm', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xfonts-100dpi', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xfonts-100dpi-transcoded', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xfonts-75dpi', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xfonts-75dpi-transcoded', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xfonts-base', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xfonts-base-transcoded', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xfonts-cyrillic', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xfonts-scalable', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xfree86-common', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xfs', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xfwp', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xlibmesa-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xlibmesa-dri', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xlibmesa-dri-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xlibmesa-gl', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xlibmesa-gl-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xlibmesa-gl-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xlibmesa-glu', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xlibmesa-glu-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xlibmesa-glu-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xlibmesa3', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xlibmesa3-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xlibosmesa-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xlibosmesa4', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xlibosmesa4-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xlibs', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xlibs-data', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xlibs-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xlibs-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xlibs-pic', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xlibs-static-dev', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xlibs-static-pic', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xmh', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xnest', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xserver-common', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xserver-xfree86', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xserver-xfree86-dbg', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xspecs', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xterm', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xutils', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xvfb', release: '3.1', reference: '4.3.0.dfsg.1-14sarge5');
deb_check(prefix: 'xfs', release: '4.0', reference: '1.0.1-7');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
