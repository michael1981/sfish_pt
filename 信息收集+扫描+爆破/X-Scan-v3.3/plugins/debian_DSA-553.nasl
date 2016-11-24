# This script was automatically generated from the dsa-553
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15390);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "553");
 script_cve_id("CVE-2004-0880", "CVE-2004-0881");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-553 security update');
 script_set_attribute(attribute: 'description', value:
'A security problem has been discovered in getmail, a POP3 and APOP
mail gatherer and forwarder.  An attacker with a shell account on the
victims host could utilise getmail to overwrite arbitrary files when
it is running as root.
For the stable distribution (woody) this problem has been fixed in
version 2.3.7-2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-553');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your getmail package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA553] DSA-553-1 getmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-553-1 getmail");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'getmail', release: '3.0', reference: '2.3.7-2');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
