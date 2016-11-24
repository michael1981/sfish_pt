# This script was automatically generated from the dsa-022
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14859);
 script_version("$Revision: 1.13 $");
 script_xref(name: "DSA", value: "022");
 script_bugtraq_id(2201);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-022 security update');
 script_set_attribute(attribute: 'description', value:
'Former versions of the exmh program used /tmp for storing
temporary files. No checks were made to ensure that nobody placed a symlink
with the same name in /tmp in the meantime and thus was vulnerable to a symlink
attack. This could lead to a malicious local user being able to overwrite any
file writable by the user executing exmh. Upstream developers have reported and
fixed this. The exmh program now use /tmp/login unless TMPDIR or EXMHTMPDIR
is set. 

We recommend you upgrade your exmh packages immediately.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-022');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-022
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA022] DSA-022-1 exmh");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_cve_id("CVE-2001-0125");
 script_summary(english: "DSA-022-1 exmh");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'exmh', release: '2.2', reference: '2.1.1-1.1');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
