# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200407-10.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description)
{
 script_id(14543);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200407-10");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200407-10 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200407-10
(rsync: Directory traversal in rsync daemon)


    When rsyncd is used without chroot ("use chroot = false" in the rsyncd.conf
    file), the paths sent by the client are not checked thoroughly enough. If
    rsyncd is used with read-write permissions ("read only = false"), this
    vulnerability can be used to write files anywhere with the rights of the
    rsyncd daemon. With default Gentoo installations, rsyncd runs in a chroot,
    without write permissions and with the rights of the "nobody" user.
  
Impact

    On affected configurations and if the rsync daemon runs under a privileged
    user, a remote client can exploit this vulnerability to completely
    compromise the host.
  
Workaround

    You should never set the rsync daemon to run with "use chroot = false". If
    for some reason you have to run rsyncd without a chroot, then you should
    not set "read only = false".
  
');
script_set_attribute(attribute:'solution', value: '
    All users should update to the latest version of the rsync package.
    # emerge sync
    # emerge -pv ">=net-misc/rsync-2.6.0-r2"
    # emerge ">=net-misc/rsync-2.6.0-r2"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0426');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200407-10.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200407-10] rsync: Directory traversal in rsync daemon');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'rsync: Directory traversal in rsync daemon');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/rsync", unaffected: make_list("ge 2.6.0-r2"), vulnerable: make_list("le 2.6.0-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
