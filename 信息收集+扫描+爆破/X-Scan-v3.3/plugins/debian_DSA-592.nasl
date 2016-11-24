# This script was automatically generated from the dsa-592
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15727);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "592");
 script_cve_id("CVE-2004-0980");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-592 security update');
 script_set_attribute(attribute: 'description', value:
'Ulf Härnhammar from the Debian Security Audit Project discovered a
format string vulnerability in ez-ipupdate, a client for many dynamic
DNS services.  This problem can only be exploited if ez-ipupdate is
running in daemon mode (most likely) with many but not all service
types.
For the stable distribution (woody) this problem has been fixed in
version 3.0.11b5-1woody2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-592');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your ez-ipupdate package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA592] DSA-592-1 ez-ipupdate");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-592-1 ez-ipupdate");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ez-ipupdate', release: '3.0', reference: '3.0.11b5-1woody2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
