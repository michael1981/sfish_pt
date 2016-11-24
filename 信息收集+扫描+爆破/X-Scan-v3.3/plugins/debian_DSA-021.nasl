# This script was automatically generated from the dsa-021
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14858);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "021");
 script_cve_id("CVE-2001-0131");
 script_bugtraq_id(2182);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-021 security update');
 script_set_attribute(attribute: 'description', value:
'WireX have found some occurrences of insecure opening of
temporary files in htdigest and htpasswd. Both programs are not installed
setuid or setgid and thus the impact should be minimal. The Apache group has
released another security bugfix which fixes a vulnerability in mod_rewrite
which may result the remote attacker to access arbitrary files on the web
server.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-021');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-021
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA021] DSA-021-1 apache");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-021-1 apache");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'apache', release: '2.2', reference: '1.3.9-13.2');
deb_check(prefix: 'apache-common', release: '2.2', reference: '1.3.9-13.2');
deb_check(prefix: 'apache-dev', release: '2.2', reference: '1.3.9-13.2');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
