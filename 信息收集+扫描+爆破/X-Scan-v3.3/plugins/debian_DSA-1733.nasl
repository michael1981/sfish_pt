# This script was automatically generated from the dsa-1733
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35764);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1733");
 script_cve_id("CVE-2008-2712", "CVE-2008-3074", "CVE-2008-3075", "CVE-2008-3076", "CVE-2008-4101");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1733 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been found in vim, an enhanced vi editor.
The Common Vulnerabilities and Exposures project identifies the
following problems:
CVE-2008-2712
    Jan Minar discovered that vim did not properly sanitise inputs
    before invoking the execute or system functions inside vim
    scripts. This could lead to the execution of arbitrary code.
CVE-2008-3074
    Jan Minar discovered that the tar plugin of vim did not properly
    sanitise the filenames in the tar archive or the name of the
    archive file itself, making it prone to arbitrary code execution.
CVE-2008-3075
    Jan Minar discovered that the zip plugin of vim did not properly
    sanitise the filenames in the zip archive or the name of the
    archive file itself, making it prone to arbitrary code execution.
CVE-2008-3076
    Jan Minar discovered that the netrw plugin of vim did not properly
    sanitise the filenames or directory names it is given. This could
    lead to the execution of arbitrary code.
CVE-2008-4101
    Ben Schmidt discovered that vim did not properly escape characters
    when performing keyword or tag lookups. This could lead to the
    execution of arbitrary code.
For the oldstable distribution (etch), these problems have been fixed in
version 1:7.0-122+1etch5.
For the stable distribution (lenny), these problems have been fixed in
version 1:7.1.314-3+lenny1, which was already included in the lenny
release.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1733');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2009/dsa-1733
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1733] DSA-1733-1 vim");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1733-1 vim");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'vim', release: '4.0', reference: '7.0-122+1etch5');
deb_check(prefix: 'vim-common', release: '4.0', reference: '7.0-122+1etch5');
deb_check(prefix: 'vim-doc', release: '4.0', reference: '7.0-122+1etch5');
deb_check(prefix: 'vim-full', release: '4.0', reference: '7.0-122+1etch5');
deb_check(prefix: 'vim-gnome', release: '4.0', reference: '7.0-122+1etch5');
deb_check(prefix: 'vim-gtk', release: '4.0', reference: '7.0-122+1etch5');
deb_check(prefix: 'vim-gui-common', release: '4.0', reference: '7.0-122+1etch5');
deb_check(prefix: 'vim-lesstif', release: '4.0', reference: '7.0-122+1etch5');
deb_check(prefix: 'vim-perl', release: '4.0', reference: '7.0-122+1etch5');
deb_check(prefix: 'vim-python', release: '4.0', reference: '7.0-122+1etch5');
deb_check(prefix: 'vim-ruby', release: '4.0', reference: '7.0-122+1etch5');
deb_check(prefix: 'vim-runtime', release: '4.0', reference: '7.0-122+1etch5');
deb_check(prefix: 'vim-tcl', release: '4.0', reference: '7.0-122+1etch5');
deb_check(prefix: 'vim-tiny', release: '4.0', reference: '7.0-122+1etch5');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
