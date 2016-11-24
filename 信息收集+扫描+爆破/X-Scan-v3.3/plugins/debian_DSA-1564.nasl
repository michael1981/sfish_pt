# This script was automatically generated from the dsa-1564
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(32126);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1564");
 script_cve_id("CVE-2007-0540", "CVE-2007-3639", "CVE-2007-4153", "CVE-2007-4154");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1564 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in WordPress,
a weblog manager. The Common Vulnerabilities and Exposures project
identifies the following problems:
CVE-2007-3639
    Insufficient input sanitising allowed for remote attackers to
    redirect visitors to external websites.
CVE-2007-4153
    Multiple cross-site scripting vulnerabilities allowed remote
    authenticated administrators to inject arbitrary web script or HTML.
CVE-2007-4154
    SQL injection vulnerability allowed allowed remote authenticated
    administrators to execute arbitrary SQL commands.
CVE-2007-0540
    WordPress allows remote attackers to cause a denial of service
    (bandwidth or thread consumption) via pingback service calls with
    a source URI that corresponds to a file with a binary content type,
    which is downloaded even though it cannot contain usable pingback data.
    Insufficient input sanitising caused an attacker with a normal user
    account to access the administrative interface.
For the stable distribution (etch), these problems have been fixed in version
2.0.10-1etch2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1564');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your wordpress package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1564] DSA-1564-1 wordpress");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1564-1 wordpress");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'wordpress', release: '4.0', reference: '2.0.10-1etch2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
