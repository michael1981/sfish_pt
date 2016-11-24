# This script was automatically generated from the dsa-801
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19571);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "801");
 script_cve_id("CVE-2005-2496");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-801 security update');
 script_set_attribute(attribute: 'description', value:
'SuSE developers discovered that ntp confuses the given group id with
the group id of the given user when called with a group id on the
commandline that is specified as a string and not as a numeric gid,
which causes ntpd to run with different privileges than intended.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 4.2.0a+stable-2sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-801');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your ntp-server package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA801] DSA-801-1 ntp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-801-1 ntp");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ntp', release: '3.1', reference: '4.2.0a+stable-2sarge1');
deb_check(prefix: 'ntp-doc', release: '3.1', reference: '4.2.0a+stable-2sarge1');
deb_check(prefix: 'ntp-refclock', release: '3.1', reference: '4.2.0a+stable-2sarge1');
deb_check(prefix: 'ntp-server', release: '3.1', reference: '4.2.0a+stable-2sarge1');
deb_check(prefix: 'ntp-simple', release: '3.1', reference: '4.2.0a+stable-2sarge1');
deb_check(prefix: 'ntpdate', release: '3.1', reference: '4.2.0a+stable-2sarge1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
