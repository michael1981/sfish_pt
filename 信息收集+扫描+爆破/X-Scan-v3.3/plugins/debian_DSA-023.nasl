# This script was automatically generated from the dsa-023
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14860);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "023");
 script_cve_id("CVE-2001-0361");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-023 security update');
 script_set_attribute(attribute: 'description', value:
'People at WireX have found several potential insecure uses of temporary files in programs provided by INN2. Some of them only lead to a vulnerability to symlink attacks if the temporary directory was set to /tmp or /var/tmp, which is the case in many installations, at least in Debian packages. An attacker could overwrite any file owned by the news system administrator, i.e. owned by news.news.
Michal Zalewski found an exploitable buffer overflow with regard to cancel messages and their verification. This bug did only show up if "verifycancels" was enabled in inn.conf which is not the default and has been disrecommended by upstream.
Andi Kleen found a bug in INN2 that makes innd crash for two byte headers. There is a chance this can only be exploited with uucp.

We recommend you upgrade your inn2 packages immediately.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-023');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-023
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA023] DSA-023-1 inn2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-023-1 inn2");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'inn2', release: '2.2', reference: '2.2.2.2000.01.31-4.1');
deb_check(prefix: 'inn2-dev', release: '2.2', reference: '2.2.2.2000.01.31-4.1');
deb_check(prefix: 'inn2-inews', release: '2.2', reference: '2.2.2.2000.01.31-4.1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
