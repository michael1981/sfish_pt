# This script was automatically generated from the dsa-1291
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25228);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1291");
 script_cve_id("CVE-2007-2444", "CVE-2007-2446", "CVE-2007-2447");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1291 security update');
 script_set_attribute(attribute: 'description', value:
'Several issues have been identified in Samba, the SMB/CIFS
file- and print-server implementation for GNU/Linux.
CVE-2007-2444
    When translating SIDs to/from names using Samba local list of user and
    group accounts, a logic error in the smbd daemon\'s internal security
    stack may result in a transition to the root user id rather than the
    non-root user.  The user is then able to temporarily issue SMB/CIFS
    protocol operations as the root user.  This window of opportunity may
    allow the attacker to establish addition means of gaining root access to
    the server.
CVE-2007-2446
    Various bugs in Samba\'s NDR parsing can allow a user to send specially
    crafted MS-RPC requests that will overwrite the heap space with user
    defined data.
CVE-2007-2447
    Unescaped user input parameters are passed as arguments to /bin/sh
    allowing for remote command execution.
For the stable distribution (etch), these problems have been fixed in
version 3.0.24-6etch1.
For the testing and unstable distributions (lenny and sid,
respectively), these problems have been fixed in version 3.0.25-1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1291');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your samba package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1291] DSA-1291-1 samba");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1291-1 samba");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libpam-smbpass', release: '4.0', reference: '3.0.24-6etch1');
deb_check(prefix: 'libsmbclient', release: '4.0', reference: '3.0.24-6etch1');
deb_check(prefix: 'libsmbclient-dev', release: '4.0', reference: '3.0.24-6etch1');
deb_check(prefix: 'python-samba', release: '4.0', reference: '3.0.24-6etch1');
deb_check(prefix: 'samba', release: '4.0', reference: '3.0.24-6etch1');
deb_check(prefix: 'samba-common', release: '4.0', reference: '3.0.24-6etch1');
deb_check(prefix: 'samba-dbg', release: '4.0', reference: '3.0.24-6etch1');
deb_check(prefix: 'samba-doc', release: '4.0', reference: '3.0.24-6etch1');
deb_check(prefix: 'samba-doc-pdf', release: '4.0', reference: '3.0.24-6etch1');
deb_check(prefix: 'smbclient', release: '4.0', reference: '3.0.24-6etch1');
deb_check(prefix: 'smbfs', release: '4.0', reference: '3.0.24-6etch1');
deb_check(prefix: 'swat', release: '4.0', reference: '3.0.24-6etch1');
deb_check(prefix: 'winbind', release: '4.0', reference: '3.0.24-6etch1');
deb_check(prefix: 'samba', release: '5.0', reference: '3.0.25-1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
