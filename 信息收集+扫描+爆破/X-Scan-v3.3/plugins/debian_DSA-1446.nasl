# This script was automatically generated from the dsa-1446
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(29840);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1446");
 script_cve_id("CVE-2007-6450", "CVE-2007-6451");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1446 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in the Wireshark
network traffic analyzer, which may lead to denial of service. The
Common Vulnerabilities and Exposures project identifies the following
problems:

CVE-2007-6450
    
    The RPL dissector could be tricked into an infinite loop.
    
CVE-2007-6451
    
    The CIP dissector could be tricked into excessive memory
    allocation.
    

For the old stable distribution (sarge), these problems have been fixed in
version 0.10.10-2sarge11. (In Sarge Wireshark used to be called Ethereal).


For the stable distribution (etch), these problems have been fixed in
version 0.99.4-5.etch.2.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1446');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your wireshark packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1446] DSA-1446-1 wireshark");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1446-1 wireshark");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ethereal', release: '3.1', reference: '0.10.10-2sarge11');
deb_check(prefix: 'ethereal-common', release: '3.1', reference: '0.10.10-2sarge11');
deb_check(prefix: 'ethereal-dev', release: '3.1', reference: '0.10.10-2sarge11');
deb_check(prefix: 'tethereal', release: '3.1', reference: '0.10.10-2sarge11');
deb_check(prefix: 'ethereal', release: '4.0', reference: '0.99.4-5.etch.2');
deb_check(prefix: 'ethereal-common', release: '4.0', reference: '0.99.4-5.etch.2');
deb_check(prefix: 'ethereal-dev', release: '4.0', reference: '0.99.4-5.etch.2');
deb_check(prefix: 'tethereal', release: '4.0', reference: '0.99.4-5.etch.2');
deb_check(prefix: 'tshark', release: '4.0', reference: '0.99.4-5.etch.2');
deb_check(prefix: 'wireshark', release: '4.0', reference: '0.99.4-5.etch.2');
deb_check(prefix: 'wireshark-common', release: '4.0', reference: '0.99.4-5.etch.2');
deb_check(prefix: 'wireshark-dev', release: '4.0', reference: '0.99.4-5.etch.2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
