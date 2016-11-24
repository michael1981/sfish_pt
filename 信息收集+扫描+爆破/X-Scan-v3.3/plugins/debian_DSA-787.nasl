# This script was automatically generated from the dsa-787
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19530);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "787");
 script_cve_id("CVE-2005-1855", "CVE-2005-1856");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-787 security update');
 script_set_attribute(attribute: 'description', value:
'Two bugs have been found in backup-manager, a command-line driven
backup utility.  The Common Vulnerabilities and Exposures project
identifies the following problems:
    Jeroen Vermeulen discovered that backup files are created with
    default permissions making them world readable, even though they
    may contain sensitive information.
    Sven Joachim discovered that the optional CD-burning feature of
    backup-manager uses a hardcoded filename in a world-writable
    directory for logging.  This can be subject to a symlink attack.
The old stable distribution (woody) does not provide the
backup-manager package.
For the stable distribution (sarge) these problems have been fixed in
version 0.5.7-1sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-787');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your backup-manager package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA787] DSA-787-1 backup-manager");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-787-1 backup-manager");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'backup-manager', release: '3.1', reference: '0.5.7-1sarge1');
deb_check(prefix: 'backup', release: '3.1', reference: '0.5.7-1sarge1');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
