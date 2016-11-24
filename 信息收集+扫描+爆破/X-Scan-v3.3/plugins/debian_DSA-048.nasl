# This script was automatically generated from the dsa-048
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14885);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "048");
 script_cve_id("CVE-2001-0406");
 script_bugtraq_id(2617);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-048 security update');
 script_set_attribute(attribute: 'description', value:
'Marcus Meissner discovered that samba was not creating temporary
files safely in two places:


when a remote user queried a printer queue samba would create a
    temporary file in which the queue data would be written. This was being
    done using a predictable filename, and insecurely, allowing a local
    attacker to trick samba into overwriting arbitrary files.
smbclient "more" and "mput" commands also created temporary files
    in /tmp insecurely.


Both problems have been fixed in version 2.0.7-3.2, and we recommend
that you upgrade your samba package immediately. (This problem is also fixed
in the Samba 2.2 codebase.)

Note: DSA-048-1 included an incorrectly compiled sparc package, which
the second edition fixed.

The third edition of the advisory was made because Marc Jacobsen from HP
discovered that the security fixes from samba 2.0.8 did not fully fix the
/tmp symlink attack problem. The samba team released version 2.0.9 to fix
that, and those fixes have been added to version 2.0.7-3.3 of the Debian
samba packages.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-048');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-048
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA048] DSA-048-3 samba");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-048-3 samba");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'samba', release: '2.2', reference: '2.0.7-3.3');
deb_check(prefix: 'samba-common', release: '2.2', reference: '2.0.7-3.3');
deb_check(prefix: 'samba-doc', release: '2.2', reference: '2.0.7-3.3');
deb_check(prefix: 'smbclient', release: '2.2', reference: '2.0.7-3.3');
deb_check(prefix: 'smbfs', release: '2.2', reference: '2.0.7-3.3');
deb_check(prefix: 'swat', release: '2.2', reference: '2.0.7-3.3');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
