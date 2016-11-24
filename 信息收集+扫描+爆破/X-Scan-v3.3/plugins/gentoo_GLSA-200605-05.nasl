# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200605-05.xml
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
 script_id(21347);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200605-05");
 script_cve_id("CVE-2006-2083");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200605-05 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200605-05
(rsync: Potential integer overflow)


    An integer overflow was found in the receive_xattr function from
    the extended attributes patch (xattr.c) for rsync. The vulnerable
    function is only present when the "acl" USE flag is set.
  
Impact

    A remote attacker with write access to an rsync module could craft
    malicious extended attributes which would trigger the integer overflow,
    potentially resulting in the execution of arbitrary code with the
    rights of the rsync daemon.
  
Workaround

    Do not provide write access to an rsync module to untrusted
    parties.
  
');
script_set_attribute(attribute:'solution', value: '
    All rsync users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/rsync-2.6.8"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2083');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200605-05.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200605-05] rsync: Potential integer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'rsync: Potential integer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/rsync", unaffected: make_list("ge 2.6.8"), vulnerable: make_list("lt 2.6.8")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
