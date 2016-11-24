# This script was automatically generated from the dsa-1364
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25964);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "1364");
 script_cve_id("CVE-2007-2438", "CVE-2007-2953");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1364 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in the vim editor. The Common
Vulnerabilities and Exposures project identifies the following problems:
CVE-2007-2953
    Ulf Härnhammar discovered that a format string flaw in helptags_one() from
    src/ex_cmds.c (triggered through the <q>helptags</q> command) can lead to the
    execution of arbitrary code.
CVE-2007-2438
    Editors often provide a way to embed editor configuration commands (aka
    modelines) which are executed once a file is opened. Harmful commands
    are filtered by a sandbox mechanism. It was discovered that function
    calls to writefile(), feedkeys() and system() were not filtered, allowing
    shell command execution with a carefully crafted file opened in vim.
This updated advisory repairs issues with missing files in the packages
for the oldstable distribution (sarge) for the alpha, mips, and mipsel
architectures.
For the oldstable distribution (sarge) these problems have been fixed in
version 6.3-071+1sarge2. Sarge is not affected by CVE-2007-2438.
For the stable distribution (etch) these problems have been fixed
in version 7.0-122+1etch3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1364');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your vim packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1364] DSA-1364-2 vim");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1364-2 vim");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'vim', release: '3.1', reference: '6.3-071+1sarge2');
deb_check(prefix: 'vim-common', release: '3.1', reference: '6.3-071+1sarge2');
deb_check(prefix: 'vim-doc', release: '3.1', reference: '6.3-071+1sarge2');
deb_check(prefix: 'vim-full', release: '3.1', reference: '6.3-071+1sarge2');
deb_check(prefix: 'vim-gnome', release: '3.1', reference: '6.3-071+1sarge2');
deb_check(prefix: 'vim-gtk', release: '3.1', reference: '6.3-071+1sarge2');
deb_check(prefix: 'vim-lesstif', release: '3.1', reference: '6.3-071+1sarge2');
deb_check(prefix: 'vim-perl', release: '3.1', reference: '6.3-071+1sarge2');
deb_check(prefix: 'vim-python', release: '3.1', reference: '6.3-071+1sarge2');
deb_check(prefix: 'vim-ruby', release: '3.1', reference: '6.3-071+1sarge2');
deb_check(prefix: 'vim-tcl', release: '3.1', reference: '6.3-071+1sarge2');
deb_check(prefix: 'vim', release: '4.0', reference: '7.0-122+1etch3');
deb_check(prefix: 'vim-common', release: '4.0', reference: '7.0-122+1etch3');
deb_check(prefix: 'vim-doc', release: '4.0', reference: '7.0-122+1etch3');
deb_check(prefix: 'vim-full', release: '4.0', reference: '7.0-122+1etch3');
deb_check(prefix: 'vim-gnome', release: '4.0', reference: '7.0-122+1etch3');
deb_check(prefix: 'vim-gtk', release: '4.0', reference: '7.0-122+1etch3');
deb_check(prefix: 'vim-gui-common', release: '4.0', reference: '7.0-122+1etch3');
deb_check(prefix: 'vim-lesstif', release: '4.0', reference: '7.0-122+1etch3');
deb_check(prefix: 'vim-perl', release: '4.0', reference: '7.0-122+1etch3');
deb_check(prefix: 'vim-python', release: '4.0', reference: '7.0-122+1etch3');
deb_check(prefix: 'vim-ruby', release: '4.0', reference: '7.0-122+1etch3');
deb_check(prefix: 'vim-runtime', release: '4.0', reference: '7.0-122+1etch3');
deb_check(prefix: 'vim-tcl', release: '4.0', reference: '7.0-122+1etch3');
deb_check(prefix: 'vim-tiny', release: '4.0', reference: '7.0-122+1etch3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
