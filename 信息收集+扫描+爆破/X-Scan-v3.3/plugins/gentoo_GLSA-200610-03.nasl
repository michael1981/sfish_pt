# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200610-03.xml
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
 script_id(22522);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200610-03");
 script_cve_id("CVE-2006-1168");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200610-03 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200610-03
(ncompress: Buffer Underflow)


    Tavis Ormandy of the Google Security Team discovered a static buffer
    underflow in ncompress.
  
Impact

    An attacker could create a specially crafted LZW archive, that when
    decompressed by a user or automated system would result in the
    execution of arbitrary code with the permissions of the user invoking
    the utility.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All ncompress users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-arch/ncompress-4.2.4.1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1168');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200610-03.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200610-03] ncompress: Buffer Underflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ncompress: Buffer Underflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-arch/ncompress", unaffected: make_list("ge 4.2.4.1"), vulnerable: make_list("lt 4.2.4.1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
