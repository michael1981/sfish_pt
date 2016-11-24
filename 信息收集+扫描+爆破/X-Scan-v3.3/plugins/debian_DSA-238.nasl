# This script was automatically generated from the dsa-238
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15075);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "238");
 script_cve_id("CVE-2002-1393");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-238 security update');
 script_set_attribute(attribute: 'description', value:
'The KDE team discovered several vulnerabilities in the K Desktop
Environment.  In some instances KDE fails to properly quote parameters
of instructions passed to a command shell for execution.  These
parameters may incorporate data such as URLs, filenames and e-mail
addresses, and this data may be provided remotely to a victim in an
e-mail, a webpage or files on a network filesystem or other untrusted
source.
By carefully crafting such data an attacker might be able to execute
arbitrary commands on a vulnerable system using the victim\'s account and
privileges.  The KDE Project is not aware of any existing exploits of
these vulnerabilities.  The patches also provide better safe guards
and check data from untrusted sources more strictly in multiple
places.
For the current stable distribution (woody), these problems have been fixed
in version 2.2.2-5.2.
The old stable distribution (potato) does not contain KDE packages.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-238');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your KDE packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA238] DSA-238-1 kdepim");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-238-1 kdepim");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'kandy', release: '3.0', reference: '2.2.2-5.2');
deb_check(prefix: 'kdepim-dev', release: '3.0', reference: '2.2.2-5.2');
deb_check(prefix: 'kdepim-libs', release: '3.0', reference: '2.2.2-5.2');
deb_check(prefix: 'korganizer', release: '3.0', reference: '2.2.2-5.2');
deb_check(prefix: 'kpilot', release: '3.0', reference: '2.2.2-5.2');
deb_check(prefix: 'kdepim', release: '3.0', reference: '2.2.2-5.2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
