# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200509-15.xml
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
 script_id(19814);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200509-15");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200509-15 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200509-15
(util-linux: umount command validation error)


    When a regular user mounts a filesystem, they are subject to
    restrictions in the /etc/fstab configuration file. David Watson
    discovered that when unmounting a filesystem with the \'-r\' option, the
    read-only bit is set, while other bits, such as nosuid or nodev, are
    not set, even if they were previously.
  
Impact

    An unprivileged user facing nosuid or nodev restrictions can
    umount -r a filesystem clearing those bits, allowing applications to be
    executed suid, or have device nodes interpreted. In the case where the
    user can freely modify the contents of the filesystem, privilege
    escalation may occur as a custom program may execute with suid
    permissions.
  
Workaround

    Two workarounds exist, first, the suid bit can be removed from the
    umount utility, or users can be restricted from mounting and unmounting
    filesystems in /etc/fstab.
  
');
script_set_attribute(attribute:'solution', value: '
    All util-linux users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=sys-apps/util-linux-2.12q-r3"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2005-2876');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200509-15.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200509-15] util-linux: umount command validation error');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'util-linux: umount command validation error');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "sys-apps/util-linux", unaffected: make_list("ge 2.12q-r3"), vulnerable: make_list("lt 2.12q-r3")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
