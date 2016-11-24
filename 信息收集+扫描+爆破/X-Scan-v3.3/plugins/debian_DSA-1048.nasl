# This script was automatically generated from the dsa-1048
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22590);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1048");
 script_cve_id("CVE-2005-3559", "CVE-2006-1827");
 script_bugtraq_id(15336);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1048 security update');
 script_set_attribute(attribute: 'description', value:
'Several problems have been discovered in Asterisk, an Open Source
Private Branch Exchange (telephone control center).  The Common
Vulnerabilities and Exposures project identifies the following
problems:
CVE-2005-3559
    Adam Pointon discovered that due to missing input sanitising it is
    possible to retrieve recorded phone messages for a different
    extension.
CVE-2006-1827
    Emmanouel Kellinis discovered an integer signedness error that
    could trigger a buffer overflow and hence allow the execution of
    arbitrary code.
For the old stable distribution (woody) this problem has been fixed in
version 0.1.11-3woody1.
For the stable distribution (sarge) this problem has been fixed in
version 1.0.7.dfsg.1-2sarge2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1048');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your asterisk package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1048] DSA-1048-1 asterisk");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1048-1 asterisk");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'asterisk', release: '3.0', reference: '0.1.11-3woody1');
deb_check(prefix: 'asterisk', release: '3.1', reference: '1.0.7.dfsg.1-2sarge2');
deb_check(prefix: 'asterisk-config', release: '3.1', reference: '1.0.7.dfsg.1-2sarge2');
deb_check(prefix: 'asterisk-dev', release: '3.1', reference: '1.0.7.dfsg.1-2sarge2');
deb_check(prefix: 'asterisk-doc', release: '3.1', reference: '1.0.7.dfsg.1-2sarge2');
deb_check(prefix: 'asterisk-gtk-console', release: '3.1', reference: '1.0.7.dfsg.1-2sarge2');
deb_check(prefix: 'asterisk-h323', release: '3.1', reference: '1.0.7.dfsg.1-2sarge2');
deb_check(prefix: 'asterisk-sounds-main', release: '3.1', reference: '1.0.7.dfsg.1-2sarge2');
deb_check(prefix: 'asterisk-web-vmail', release: '3.1', reference: '1.0.7.dfsg.1-2sarge2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
