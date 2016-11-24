# This script was automatically generated from the dsa-1516
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(31587);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1516");
 script_cve_id("CVE-2008-1199", "CVE-2008-1218");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1516 security update');
 script_set_attribute(attribute: 'description', value:
'Prior to this update, the default configuration for Dovecot used by
Debian runs the server daemons with group mail privileges.  This means
that users with write access to their mail directory on the server
(for example, through an SSH login) could read and also delete via a symbolic link mailboxes owned by
other users for which they do not have direct access
(CVE-2008-1199).  In addition, an internal interpretation conflict in
password handling has been addressed proactively, even though it is
not known to be exploitable (CVE-2008-1218).
Note that applying this update requires manual action: The
configuration setting <q>mail_extra_groups = mail</q> has been replaced
with <q>mail_privileged_group = mail</q>.  The update will show a
configuration file conflict in /etc/dovecot/dovecot.conf.  It is
recommended that you keep the currently installed configuration file,
and change the affected line.  For your reference, the sample
configuration (without your local changes) will have been written to
/etc/dovecot/dovecot.conf.dpkg-new.
If your current configuration uses mail_extra_groups with a value
different from <q>mail</q>, you may have to resort to the
mail_access_groups configuration directive.
For the old stable distribution (sarge), no updates are provided.
We recommend that you consider upgrading to the stable distribution.
For the stable distribution (etch), these problems have been fixed in
version 1.0.rc15-2etch4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1516');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2008/dsa-1516
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1516] DSA-1516-1 dovecot");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1516-1 dovecot");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'dovecot-common', release: '4.0', reference: '1.0.rc15-2etch4');
deb_check(prefix: 'dovecot-imapd', release: '4.0', reference: '1.0.rc15-2etch4');
deb_check(prefix: 'dovecot-pop3d', release: '4.0', reference: '1.0.rc15-2etch4');
deb_check(prefix: 'dovecot', release: '4.0', reference: '1.0.rc15-2etch4');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
