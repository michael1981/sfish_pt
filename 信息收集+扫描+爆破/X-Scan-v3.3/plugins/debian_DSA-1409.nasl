# This script was automatically generated from the dsa-1409
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(28298);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1409");
 script_cve_id("CVE-2007-4572", "CVE-2007-5398");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1409 security update');
 script_set_attribute(attribute: 'description', value:
'This update fixes all currently known regressions introduced with
the previous two revisions of DSA-1409.
The original text is reproduced below:
Several local/remote vulnerabilities have been discovered in samba,
a LanManager-like file and printer server for Unix. The Common 
Vulnerabilities and Exposures project identifies the following problems:
CVE-2007-5398
   Alin Rad Pop of Secunia Research discovered that nmbd did not properly
   check the length of netbios packets. When samba is configured as a WINS
   server, a remote attacker could send multiple crafted requests resulting
   in the execution of arbitrary code with root privileges.
CVE-2007-4572
   Samba developers discovered that nmbd could be made to overrun a buffer
   during the processing of GETDC logon server requests.  When samba is
   configured as a Primary or Backup Domain Controller, a remote attacker
   could send malicious logon requests and possibly cause a denial of
   service.
For the old stable distribution (sarge), these problems have been fixed in
version 3.0.14a-3sarge10.
For the stable distribution (etch), these problems have been fixed in
version 3.0.24-6etch8.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1409');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your samba packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1409] DSA-1409-3 samba");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1409-3 samba");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libpam-smbpass', release: '3.1', reference: '3.0.14a-3sarge10');
deb_check(prefix: 'libsmbclient', release: '3.1', reference: '3.0.14a-3sarge10');
deb_check(prefix: 'libsmbclient-dev', release: '3.1', reference: '3.0.14a-3sarge10');
deb_check(prefix: 'python2.3-samba', release: '3.1', reference: '3.0.14a-3sarge10');
deb_check(prefix: 'samba', release: '3.1', reference: '3.0.14a-3sarge10');
deb_check(prefix: 'samba-common', release: '3.1', reference: '3.0.14a-3sarge10');
deb_check(prefix: 'samba-dbg', release: '3.1', reference: '3.0.14a-3sarge10');
deb_check(prefix: 'samba-doc', release: '3.1', reference: '3.0.14a-3sarge10');
deb_check(prefix: 'smbclient', release: '3.1', reference: '3.0.14a-3sarge10');
deb_check(prefix: 'smbfs', release: '3.1', reference: '3.0.14a-3sarge10');
deb_check(prefix: 'swat', release: '3.1', reference: '3.0.14a-3sarge10');
deb_check(prefix: 'winbind', release: '3.1', reference: '3.0.14a-3sarge10');
deb_check(prefix: 'libpam-smbpass', release: '4.0', reference: '3.0.24-6etch8');
deb_check(prefix: 'libsmbclient', release: '4.0', reference: '3.0.24-6etch8');
deb_check(prefix: 'libsmbclient-dev', release: '4.0', reference: '3.0.24-6etch8');
deb_check(prefix: 'python-samba', release: '4.0', reference: '3.0.24-6etch8');
deb_check(prefix: 'samba', release: '4.0', reference: '3.0.24-6etch8');
deb_check(prefix: 'samba-common', release: '4.0', reference: '3.0.24-6etch8');
deb_check(prefix: 'samba-dbg', release: '4.0', reference: '3.0.24-6etch8');
deb_check(prefix: 'samba-doc', release: '4.0', reference: '3.0.24-6etch8');
deb_check(prefix: 'samba-doc-pdf', release: '4.0', reference: '3.0.24-6etch8');
deb_check(prefix: 'smbclient', release: '4.0', reference: '3.0.24-6etch8');
deb_check(prefix: 'smbfs', release: '4.0', reference: '3.0.24-6etch8');
deb_check(prefix: 'swat', release: '4.0', reference: '3.0.24-6etch8');
deb_check(prefix: 'winbind', release: '4.0', reference: '3.0.24-6etch8');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
