# This script was automatically generated from the dsa-316
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15153);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "316");
 script_cve_id("CVE-2003-0358", "CVE-2003-0359");
 script_bugtraq_id(6806, 7953);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-316 security update');
 script_set_attribute(attribute: 'description', value:
'The nethack and slashem packages are vulnerable to a buffer overflow exploited via a
long \'-s\' command line option.  This vulnerability could be used by an
attacker to gain gid \'games\' on a system where nethack is installed.
Additionally, some setgid binaries in the nethack package have
incorrect permissions, which could allow a user who gains gid \'games\'
to replace these binaries, potentially causing other users to execute
malicious code when they run nethack.
Note that slashem does not contain the file permission problem
CVE-2003-0359.
For the stable distribution (woody) these problems have been fixed in
version 3.4.0-3.0woody3.
For the old stable distribution (potato) these problems have been fixed in
version 3.3.0-7potato1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-316');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-316
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA316] DSA-316-1 nethack");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-316-1 nethack");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'nethack', release: '2.2', reference: '3.3.0-7potato1');
deb_check(prefix: 'nethack', release: '3.0', reference: '3.4.0-3.0woody3');
deb_check(prefix: 'nethack-common', release: '3.0', reference: '3.4.0-3.0woody3');
deb_check(prefix: 'nethack-gnome', release: '3.0', reference: '3.4.0-3.0woody3');
deb_check(prefix: 'nethack-qt', release: '3.0', reference: '3.4.0-3.0woody3');
deb_check(prefix: 'nethack-x11', release: '3.0', reference: '3.4.0-3.0woody3');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
