# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200611-24.xml
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
 script_id(23746);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200611-24");
 script_cve_id("CVE-2006-4335", "CVE-2006-4336", "CVE-2006-4337", "CVE-2006-4338");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200611-24 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200611-24
(LHa: Multiple vulnerabilities)


    Tavis Ormandy of the Google Security Team discovered several
    vulnerabilities in the LZH decompression component used by LHa. The
    make_table function of unlzh.c contains an array index error and a
    buffer overflow vulnerability. The build_tree function of unpack.c
    contains a buffer underflow vulnerability. Additionally, unlzh.c
    contains a code that could run in an infinite loop.
  
Impact

    By enticing a user to uncompress a specially crafted archive, a remote
    attacker could cause a Denial of Service by CPU consumption or execute
    arbitrary code with the rights of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All LHa users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-arch/lha-114i-r6"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4335');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4336');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4337');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4338');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200611-24.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200611-24] LHa: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'LHa: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-arch/lha", unaffected: make_list("ge 114i-r6"), vulnerable: make_list("lt 114i-r6")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
