# This script was automatically generated from the dsa-1259
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(24346);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1259");
 script_cve_id("CVE-2006-5867");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1259 security update');
 script_set_attribute(attribute: 'description', value:
'Isaac Wilcox discovered that fetchmail, a popular mail retrieval and
forwarding utility, insufficiently enforces encryption of connections,
which might lead to information disclosure.
For the stable distribution (sarge) this problem has been fixed in
version 6.2.5-12sarge5.
For the upcoming stable distribution (etch) this problem has been
fixed in version 6.3.6-1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1259');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your fetchmail package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1259] DSA-1259-1 fetchmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1259-1 fetchmail");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'fetchmail', release: '3.1', reference: '6.2.5-12sarge5');
deb_check(prefix: 'fetchmail-ssl', release: '3.1', reference: '6.2.5-12sarge5');
deb_check(prefix: 'fetchmailconf', release: '3.1', reference: '6.2.5-12sarge5');
deb_check(prefix: 'fetchmail', release: '4.0', reference: '6.3.6-1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
