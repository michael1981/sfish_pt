# This script was automatically generated from the dsa-1022
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22564);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1022");
 script_cve_id("CVE-2005-3146", "CVE-2005-3147", "CVE-2005-3148");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1022 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in the backup utility 
storebackup. The Common Vulnerabilities and Exposures project identifies
the following problems:
CVE-2005-3146
    Storebackup creates a temporary file predictably, which can be
    exploited to overwrite arbitrary files on the system with a symlink
    attack.
CVE-2005-3147
    The backup root directory wasn\'t created with fixed permissions, which may lead to
       inproper permissions if the umask is too lax.
CVE-2005-3148
    The user and group rights of symlinks are set incorrectly when making
    or restoring a backup, which may leak sensitive data.
The old stable distribution (woody) doesn\'t contain storebackup packages.
For the stable distribution (sarge) these problems have been fixed in
version 1.18.4-2sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1022');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your storebackup package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1022] DSA-1022-1 storebackup");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1022-1 storebackup");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'storebackup', release: '3.1', reference: '1.18.4-2sarge1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
