# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200408-17.xml
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
 script_id(14573);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200408-17");
 script_cve_id("CVE-2004-0792");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200408-17 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200408-17
(rsync: Potential information leakage)


    The paths sent by the rsync client are not checked thoroughly enough.
    It does not affect the normal send/receive filenames that specify what
    files should be transferred. It does affect certain option paths that
    cause auxilliary files to be read or written.
  
Impact

    When rsyncd is used without chroot ("use chroot = false" in the
    rsyncd.conf file), this vulnerability could allow the listing of
    arbitrary files outside module\'s path and allow file overwriting
    outside module\'s path on rsync server configurations that allows
    uploading. Both possibilities are exposed only when chroot option is
    disabled.
  
Workaround

    You should never set the rsync daemon to run with "use chroot = false".
  
');
script_set_attribute(attribute:'solution', value: '
    All users should update to the latest version of the rsync package.
    # emerge sync
    # emerge -pv ">=net-misc/rsync-2.6.0-r3"
    # emerge ">=net-misc/rsync-2.6.0-r3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://samba.org/rsync/#security_aug04');
script_set_attribute(attribute: 'see_also', value: 'http://lists.samba.org/archive/rsync-announce/2004/000017.html');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0792');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200408-17.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200408-17] rsync: Potential information leakage');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'rsync: Potential information leakage');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/rsync", unaffected: make_list("ge 2.6.0-r3"), vulnerable: make_list("le 2.6.0-r2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
