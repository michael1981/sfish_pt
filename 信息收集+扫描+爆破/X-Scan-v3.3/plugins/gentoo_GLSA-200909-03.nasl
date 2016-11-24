# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200909-03.xml
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
 script_id(40911);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200909-03");
 script_cve_id("CVE-2009-2412");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200909-03 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200909-03
(Apache Portable Runtime, APR Utility Library: Execution of arbitrary code)


    Matt Lewis reported multiple Integer overflows in the apr_rmm_malloc(),
    apr_rmm_calloc(), and apr_rmm_realloc() functions in misc/apr_rmm.c of
    APR-Util and in memory/unix/apr_pools.c of APR, both occurring when
    aligning memory blocks.
  
Impact

    A remote attacker could entice a user to connect to a malicious server
    with software that uses the APR or act as a malicious client to a
    server that uses the APR (such as Subversion or Apache servers),
    possibly resulting in the execution of arbitrary code with the
    privileges of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Apache Portable Runtime users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose =dev-libs/apr-1.3.8
    All APR Utility Library users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose =dev-libs/apr-util-1.3.9
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2412');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200909-03.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200909-03] Apache Portable Runtime, APR Utility Library: Execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Apache Portable Runtime, APR Utility Library: Execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-libs/apr", unaffected: make_list("ge 1.3.8"), vulnerable: make_list("lt 1.3.8")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "dev-libs/apr-util", unaffected: make_list("ge 1.3.9"), vulnerable: make_list("lt 1.3.9")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
