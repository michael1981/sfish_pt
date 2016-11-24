# This script was automatically generated from the dsa-443
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15280);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "443");
 script_cve_id("CVE-2003-0690", "CVE-2004-0083", "CVE-2004-0084", "CVE-2004-0093", "CVE-2004-0094", "CVE-2004-0106");
 script_bugtraq_id(9636, 9652, 9655, 9701);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-443 security update');
 script_set_attribute(attribute: 'description', value:
'A number of vulnerabilities have been discovered in XFree86.  The corrections
are listed below with the identification from the Common
Vulnerabilities and Exposures (CVE) project:
    Buffer overflow in ReadFontAlias from dirfile.c of
    XFree86 4.1.0 through 4.3.0 allows local users and remote attackers to
    execute arbitrary code via a font alias file (font.alias) with a long
    token, a different vulnerability than CVE-2004-0084.
    Buffer overflow in the ReadFontAlias function in XFree86
    4.1.0 to 4.3.0, when using the CopyISOLatin1Lowered function, allows
    local or remote authenticated users to execute arbitrary code via a
    malformed entry in the font alias (font.alias) file, a different
    vulnerability than CVE-2004-0083.
    Miscellaneous additional flaws in XFree86\'s handling of
    font files.
    xdm does not verify whether the pam_setcred function call
    succeeds, which may allow attackers to gain root privileges by
    triggering error conditions within PAM modules, as demonstrated in
    certain configurations of the MIT pam_krb5 module.
    Denial-of-service attacks against the X
    server by clients using the GLX extension and Direct Rendering
    Infrastructure are possible due to unchecked client data (out-of-bounds
    array indexes [CVE-2004-0093] and integer signedness errors
    [CVE-2004-0094]).
Exploitation of CVE-2004-0083, CVE-2004-0084, CVE-2004-0106,
CVE-2004-0093 and CVE-2004-0094 would require a connection to the X
server.  By default, display managers in Debian start the X server
with a configuration which only accepts local connections, but if the
configuration is changed to allow remote connections, or X servers are
started by other means, then these bugs could be exploited remotely.
Since the X server usually runs with root privileges, these bugs could
potentially be exploited to gain root privileges.
No attack vector for CVE-2003-0690 is known at this time.
For the stable distribution (woody) these problems have been fixed in
version 4.1.0-16woody3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-443');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-443
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA443] DSA-443-1 xfree86");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-443-1 xfree86");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'lbxproxy', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'libdps-dev', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'libdps1', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'libdps1-dbg', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'libxaw6', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'libxaw6-dbg', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'libxaw6-dev', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'libxaw7', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'libxaw7-dbg', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'libxaw7-dev', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'proxymngr', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'twm', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'x-window-system', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'x-window-system-core', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'xbase-clients', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'xdm', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'xfonts-100dpi', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'xfonts-100dpi-transcoded', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'xfonts-75dpi', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'xfonts-75dpi-transcoded', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'xfonts-base', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'xfonts-base-transcoded', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'xfonts-cyrillic', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'xfonts-pex', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'xfonts-scalable', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'xfree86-common', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'xfs', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'xfwp', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'xlib6g', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'xlib6g-dev', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'xlibmesa-dev', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'xlibmesa3', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'xlibmesa3-dbg', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'xlibosmesa-dev', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'xlibosmesa3', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'xlibosmesa3-dbg', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'xlibs', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'xlibs-dbg', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'xlibs-dev', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'xlibs-pic', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'xmh', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'xnest', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'xprt', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'xserver-common', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'xserver-xfree86', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'xspecs', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'xterm', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'xutils', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'xvfb', release: '3.0', reference: '4.1.0-16woody3');
deb_check(prefix: 'xfree86', release: '3.0', reference: '4.1.0-16woody3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
