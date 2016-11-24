# This script was automatically generated from the dsa-966
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22832);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "966");
 script_cve_id("CVE-2006-0046");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-966 security update');
 script_set_attribute(attribute: 'description', value:
'Thomas Reifferscheid discovered that adzapper, a proxy advertisement
zapper add-on, when installed as plugin in squid, the Internet object
cache, can consume a lot of CPU resources and hence cause a denial of
service on the proxy host.
The old stable distribution (woody) does not contain an adzapper package.
For the stable distribution (sarge) this problem has been fixed in
version 20050316-1sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-966');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your adzapper package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA966] DSA-966-1 adzapper");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-966-1 adzapper");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'adzapper', release: '3.1', reference: '20050316-1sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
