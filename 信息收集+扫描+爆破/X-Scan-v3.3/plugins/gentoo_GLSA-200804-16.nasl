# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200804-16.xml
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
 script_id(32009);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200804-16");
 script_cve_id("CVE-2008-1720");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200804-16 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200804-16
(rsync: Execution of arbitrary code)


    Sebastian Krahmer of SUSE reported an integer overflow in the
    expand_item_list() function in the file util.c which might lead to a
    heap-based buffer overflow when extended attribute (xattr) support is
    enabled.
  
Impact

    A remote attacker could send a file containing specially crafted
    extended attributes to an rsync deamon, or entice a user to sync from
    an rsync server containing specially crafted files, possibly leading to
    the execution of arbitrary code.
    Please note that extended attributes are only enabled when USE="acl" is
    enabled, which is the default setting.
  
Workaround

    Disable extended attributes in the rsync daemon by setting "refuse
    options = xattrs" in the file "/etc/rsyncd.conf" (or append
    "xattrs" to an existing "refuse" statement). When synchronizing to a
    server, do not provide the "-X" parameter to rsync. You can also
    disable the "acl" USE flag for rsync and recompile the package.
  
');
script_set_attribute(attribute:'solution', value: '
    All rsync users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/rsync-2.6.9-r6"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1720');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200804-16.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200804-16] rsync: Execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'rsync: Execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/rsync", unaffected: make_list("ge 2.6.9-r6"), vulnerable: make_list("lt 2.6.9-r6")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
