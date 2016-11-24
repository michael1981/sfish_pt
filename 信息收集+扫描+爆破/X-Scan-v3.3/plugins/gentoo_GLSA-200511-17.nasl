# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200511-17.xml
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
 script_id(20261);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200511-17");
 script_cve_id("CVE-2005-3531");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200511-17 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200511-17
(FUSE: mtab corruption through fusermount)


    Thomas Biege discovered that fusermount fails to securely handle
    special characters specified in mount points.
  
Impact

    A local attacker could corrupt the contents of the /etc/mtab file
    by mounting over a maliciously-named directory using fusermount,
    potentially allowing the attacker to set unauthorized mount options.
    This is possible only if fusermount is installed setuid root, which is
    the default in Gentoo.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All FUSE users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=sys-fs/fuse-2.4.1-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3531');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200511-17.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200511-17] FUSE: mtab corruption through fusermount');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'FUSE: mtab corruption through fusermount');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "sys-fs/fuse", unaffected: make_list("ge 2.4.1-r1"), vulnerable: make_list("lt 2.4.1-r1")
)) { security_note(0); exit(0); }
exit(0, "Host is not affected");
