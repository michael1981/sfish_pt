# This script was automatically generated from the dsa-1576
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(32377);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1576");
 script_cve_id("CVE-2008-0166");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1576 security update');
 script_set_attribute(attribute: 'description', value:
'The recently announced vulnerability in Debian\'s openssl package
(DSA-1571-1, CVE-2008-0166) indirectly affects OpenSSH.  As a result,
all user and host keys generated using broken versions of the openssl
package must be considered untrustworthy, even after the openssl update
has been applied.
1. Install the security updates
   This update contains a dependency on the openssl update and will
   automatically install a corrected version of the libssl0.9.8 package,
   and a new package openssh-blacklist.
   Once the update is applied, weak user keys will be automatically
   rejected where possible (though they cannot be detected in all
   cases).  If you are using such keys for user authentication, they
   will immediately stop working and will need to be replaced (see
   step 3).
   OpenSSH host keys can be automatically regenerated when the OpenSSH
   security update is applied.  The update will prompt for confirmation
   before taking this step.
2. Update OpenSSH known_hosts files
   The regeneration of host keys will cause a warning to be displayed when
   connecting to the system using SSH until the host key is updated in the
   known_hosts file.  The warning will look like this:

@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
Someone could be eavesdropping on you right now (man-in-the-middle attack)!
It is also possible that the RSA host key has just been changed.


   In this case, the host key has simply been changed, and you should update
   the relevant known_hosts file as indicated in the error message.
   
   It is recommended that you use a trustworthy channel to exchange the
   server key.  It is found in the file /etc/ssh/ssh_host_rsa_key.pub on
   the server; it\'s fingerprint can be printed using the command:
      ssh-keygen -l -f /etc/ssh/ssh_host_rsa_key.pub
   In addition to user-specific known_hosts files, there may be a
   system-wide known hosts file /etc/ssh/ssh_known_hosts.  This is file is
   used both by the ssh client and by sshd for the hosts.equiv
   functionality.  This file needs to be updated as well.
3. Check all OpenSSH user keys
   The safest course of action is to regenerate all OpenSSH user keys,
   except where it can be established to a high degree of certainty that the
   key was generated on an unaffected system.
   Check whether your key is affected by running the ssh-vulnkey tool, included
   in the security update.  By default, ssh-vulnkey will check the standard
   location for user keys (~/.ssh/id_rsa, ~/.ssh/id_dsa and ~/.ssh/identity),
   your authorized_keys file (~/.ssh/authorized_keys and
   ~/.ssh/authorized_keys2), and the system\'s host keys
   (/etc/ssh/ssh_host_dsa_key and /etc/ssh/ssh_host_rsa_key).
   To check all your own keys, assuming they are in the standard
   locations (~/.ssh/id_rsa, ~/.ssh/id_dsa, or ~/.ssh/identity):
     ssh-vulnkey
   To check all keys on your system:
     sudo ssh-vulnkey -a
   To check a key in a non-standard location:
     ssh-vulnkey /path/to/key
   
[...]');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1576');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your openssh packages and take the
measures indicated above.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1576] DSA-1576-1 openssh");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1576-1 openssh");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'openssh-blacklist', release: '4.0', reference: '0.1.1');
deb_check(prefix: 'openssh-client', release: '4.0', reference: '4.3p2-9etch1');
deb_check(prefix: 'openssh-server', release: '4.0', reference: '4.3p2-9etch1');
deb_check(prefix: 'ssh', release: '4.0', reference: '4.3p2-9etch1');
deb_check(prefix: 'ssh-askpass-gnome', release: '4.0', reference: '4.3p2-9etch1');
deb_check(prefix: 'ssh-krb5', release: '4.0', reference: '4.3p2-9etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
